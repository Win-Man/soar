package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/XiaoMi/soar/advisor"
	"github.com/XiaoMi/soar/ast"
	"github.com/XiaoMi/soar/common"
	"github.com/XiaoMi/soar/database"
	"github.com/XiaoMi/soar/env"
	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	"github.com/percona/go-mysql/query"
)

func Hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello world")
}

func HandleAdvistor(c *gin.Context) {
	sql := c.DefaultPostForm("query", "")
	onlinedsn := c.DefaultPostForm("onlinedsn", "")
	testdsn := c.DefaultPostForm("testdsn", "")
	dbtype := c.DefaultPostForm("dbtype", "")
	fmt.Printf("Get post params: sql=%s, onlinedsn=%s, testdsn=%s, dbtype=%s\n", sql, onlinedsn, testdsn, dbtype)
	if sql == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"messages": "query parameter is required"})
	} else {
		_, advistors := getSuggest(sql, onlinedsn, testdsn, dbtype)
		c.JSON(http.StatusOK, gin.H{"messages": advistors, "origin_sql": sql})
	}
}

func HandleHealthy(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"messages": "healthy"})
}

// 合并数组
func merge(arr1 []string, arr2 []string) (res []string) {
	m := make(map[string]bool, len(arr1)+len(arr2))
	for _, v := range arr1 {
		m[v] = true
	}
	for _, v := range arr2 {
		if !m[v] {
			res = append(res, v)
		}
		m[v] = true
	}
	return res
}

// 去重数组
func unique(arr []string) (res []string) {
	m := make(map[string]bool, len(arr))
	for _, v := range arr {
		if !m[v] {
			res = append(res, v)
		}
		m[v] = true
	}
	return res
}

// 对单条 SQL 获取优化建议
func getSuggest(sql string, onlinedsn string, testdsn string, dbtype string) (string, string) {
	if sql == "" {
		return "", ""
	}
	// 全局变量
	var currentDB string // 当前 SQL 使用的 database
	// 逐条SQL给出优化建议
	var id string                                             // fingerprint.ID
	heuristicSuggest := make(map[string]advisor.Rule)         // 启发式建议
	expSuggest := make(map[string]advisor.Rule)               // EXPLAIN 解读
	idxSuggest := make(map[string]advisor.Rule)               // 索引建议
	proSuggest := make(map[string]advisor.Rule)               // Profiling 信息
	traceSuggest := make(map[string]advisor.Rule)             // Trace 信息
	mysqlSuggest := make(map[string]advisor.Rule)             // MySQL 返回的 ERROR 信息
	tables := make(map[string][]string)                       // SQL 使用的库表名
	suggestMerged := make(map[string]map[string]advisor.Rule) // 优化建议去重, key 为 sql 的 fingerprint.ID
	lineCounter := 1
	orgSQL := sql
	if strings.ToLower(dbtype) == "mysql" {
		common.Config.IgnoreRules = unique(merge(common.Config.IgnoreRules, common.Config.MySQLIgnoreRules))
	} else if strings.ToLower(dbtype) == "tidb" {
		common.Config.IgnoreRules = unique(merge(common.Config.IgnoreRules, common.Config.TiDBIgnoreRules))
	}
	if onlinedsn != "" {
		fmt.Println("onlinedsn is not empty")
		common.Config.OnlineDSN = common.ParseDSN(onlinedsn, common.Config.OnlineDSN)
		fmt.Printf("OnlineDSN:%s\n", common.FormatDSN(common.Config.OnlineDSN))
		common.Config.AllowOnlineAsTest = true
		common.Config.Explain = true
	}
	if testdsn != "" {
		fmt.Println("onlinedsn is not empty")
		common.Config.TestDSN = common.ParseDSN(testdsn, common.Config.TestDSN)
		fmt.Printf("TestDSN:%s\n", common.FormatDSN(common.Config.TestDSN))
	}
	// 环境初始化，连接检查线上环境+构建测试环境
	vEnv, rEnv := env.BuildEnv()

	// leftLineCounter
	llc := ast.LeftNewLines([]byte(orgSQL))
	lineCounter += llc

	// 去除无用的备注和空格
	// fmt.Printf("Before RemoveSQLComments: %s\n", sql)
	sql = database.RemoveSQLComments(sql)
	// fmt.Printf("After RemoveSQLComments: %s\n", sql)
	common.Log.Debug("main loop SQL: %s", sql)

	// +++++++++++++++++++++小工具集[开始]+++++++++++++++++++++++{
	fingerprint := strings.TrimSpace(query.Fingerprint(sql))
	if strings.HasPrefix(fingerprint, "use") {
		return sql, "use 语句不参与优化建议"
	}
	// SQL 签名
	id = query.Id(fingerprint)
	//TODO 根据传入的 dsn 设置 schema
	common.Config.TestDSN.Schema = ""
	currentDB = env.CurrentDB(sql, currentDB)

	tables[id] = ast.SchemaMetaInfo(sql, currentDB)
	// +++++++++++++++++++++小工具集[结束]+++++++++++++++++++++++}

	// +++++++++++++++++++++语法检查[开始]+++++++++++++++++++++++{
	//fmt.Printf("Before NewQuery4Audit: %v\n", sql)
	q, syntaxErr := advisor.NewQuery4Audit(sql)
	//fmt.Printf("After NewQuery4Audit: %v\n", q)

	// 如果语法检查出错则不需要给优化建议
	if syntaxErr != nil {
		errContent := fmt.Sprintf("At SQL %s : %v", sql, syntaxErr)
		common.Log.Warning(errContent)
		// tidb parser 语法检查给出的建议 ERR.000
		mysqlSuggest["ERR.000"] = advisor.RuleMySQLError("ERR.000", syntaxErr)
	}
	// +++++++++++++++++++++语法检查[结束]+++++++++++++++++++++++}

	// +++++++++++++++++++++启发式规则建议[开始]+++++++++++++++++++++++{
	common.Log.Debug("start of heuristic advisor Query: %s", q.Query)
	for item, rule := range advisor.HeuristicRules {
		// 去除忽略的建议检查
		okFunc := (*advisor.Query4Audit).RuleOK
		if !advisor.IsIgnoreRule(item) && &rule.Func != &okFunc {
			r := rule.Func(q)
			if r.Item == item {
				heuristicSuggest[item] = r
			}
		}
	}
	common.Log.Debug("end of heuristic advisor Query: %s", q.Query)
	// +++++++++++++++++++++启发式规则建议[结束]+++++++++++++++++++++++}
	if testdsn != "" {
		// +++++++++++++++++++++索引优化建议[开始]+++++++++++++++++++++++{
		// 如果配置了索引建议过滤规则，不进行索引优化建议
		// 在配置文件 ignore-rules 中添加 'IDX.*' 即可屏蔽索引优化建议
		common.Log.Debug("start of index advisor Query: %s", q.Query)
		//fmt.Printf("start of index advisor Query: %s\n", q.Query)
		if !advisor.IsIgnoreRule("IDX.") {
			if vEnv.BuildVirtualEnv(rEnv, q.Query) {
				idxAdvisor, err := advisor.NewAdvisor(vEnv, *rEnv, *q)
				if err != nil || (idxAdvisor == nil && vEnv.Error == nil) {
					if idxAdvisor == nil {
						// 如果 SQL 是 DDL 语句，则返回的 idxAdvisor 为 nil，可以忽略不处理
						// TODO alter table add index 语句检查索引是否已经存在
						common.Log.Debug("idxAdvisor by pass Query: %s", q.Query)
					} else {
						common.Log.Warning("advisor.NewAdvisor Error: %v", err)
					}
				} else {
					// 创建环境时没有出现错误，生成索引建议
					if vEnv.Error == nil {
						idxSuggest = idxAdvisor.IndexAdvise().Format()

						// 依赖数据字典的启发式建议
						for i, r := range idxAdvisor.HeuristicCheck(*q) {
							heuristicSuggest[i] = r
						}
					} else {
						// 根据错误号输出建议
						switch vEnv.Error.(*mysql.MySQLError).Number {
						case 1061:
							idxSuggest["IDX.001"] = advisor.Rule{
								Item:     "IDX.001",
								Severity: "L2",
								Summary:  "索引名称已存在",
								Content:  strings.Trim(strings.Split(vEnv.Error.Error(), ":")[1], " "),
								Case:     sql,
							}
						default:
							// vEnv.VEnvBuild 阶段给出的 ERROR 是 ERR.001
							delete(mysqlSuggest, "ERR.000")
							mysqlSuggest["ERR.001"] = advisor.RuleMySQLError("ERR.001", vEnv.Error)
							common.Log.Error("BuildVirtualEnv DDL Execute Error : %v", vEnv.Error)
						}
					}
				}
			} else {
				common.Log.Error("vEnv.BuildVirtualEnv Error: prepare SQL '%s' in vEnv failed.", q.Query)
			}
		}
		common.Log.Debug("end of index advisor Query: %s", q.Query)
		// +++++++++++++++++++++索引优化建议[结束]+++++++++++++++++++++++}

		// +++++++++++++++++++++EXPLAIN 建议[开始]+++++++++++++++++++++++{
		// 如果未配置 Online 或 Test 无法给 Explain 建议
		common.Log.Debug("start of explain Query: %s", q.Query)
		if !common.Config.OnlineDSN.Disable && !common.Config.TestDSN.Disable && strings.ToLower(dbtype) == "mysql" {
			// 因为 EXPLAIN 依赖数据库环境，所以把这段逻辑放在启发式建议和索引建议后面
			if common.Config.Explain {
				// 执行 EXPLAIN
				explainInfo, err := rEnv.Explain(q.Query,
					database.ExplainType[common.Config.ExplainType],
					database.ExplainFormatType[common.Config.ExplainFormat])
				if err != nil {
					// 线上环境执行失败才到测试环境 EXPLAIN，比如在用户提供建表语句及查询语句的场景
					common.Log.Warn("rEnv.Explain Warn: %v", err)
					explainInfo, err = vEnv.Explain(q.Query,
						database.ExplainType[common.Config.ExplainType],
						database.ExplainFormatType[common.Config.ExplainFormat])
					if err != nil {
						// EXPLAIN 阶段给出的 ERROR 是 ERR.002
						mysqlSuggest["ERR.002"] = advisor.RuleMySQLError("ERR.002", err)
						common.Log.Error("vEnv.Explain Error: %v", err)
					}
				}
				// 分析 EXPLAIN 结果
				if explainInfo != nil {
					expSuggest = advisor.ExplainAdvisor(explainInfo)
				} else {
					common.Log.Warn("rEnv&vEnv.Explain explainInfo nil, SQL: %s", q.Query)
				}
			}
		}
		common.Log.Debug("end of explain Query: %s", q.Query)
		// +++++++++++++++++++++ EXPLAIN 建议[结束]+++++++++++++++++++++++}
	} else {
		fmt.Println("dsn is epmpty")
	}

	// +++++++++++++++++++++打印单条 SQL 优化建议[开始]++++++++++++++++++++++++++{
	common.Log.Debug("start of print suggestions, Query: %s", q.Query)

	sug, str := advisor.FormatSuggest(q.Query, currentDB, common.Config.ReportType, heuristicSuggest, idxSuggest, expSuggest, proSuggest, traceSuggest, mysqlSuggest)
	suggestMerged[id] = sug

	fmt.Println(str)
	common.Log.Debug("end of print suggestions, Query: %s", q.Query)
	// +++++++++++++++++++++打印单条 SQL 优化建议[结束]++++++++++++++++++++++++++}
	return sql, str

}
