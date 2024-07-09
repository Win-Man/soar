$ ./bin/soar -query="select id,name from t where name = 123"  -test-dsn="root:@tcp(127.0.0.1:4000)/soar" -online-dsn="root:@tcp(127.0.0.1:4000)/soar" -allow-online-as-test=true
# Query: E3B4FC56CC28E1C5

★ ★ ★ ★ ☆ 80分

```sql

SELECT  
  id, name  
FROM  
  t  
WHERE  
  name  = 123
```

##  Explain信息

| id | select\_type | table | partitions | type | possible_keys | key | key\_len | ref | rows | filtered | scalability | Extra |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0  | NULL | *NULL* | NULL | NULL | NULL | NULL | NULL | NULL | 0 | 0.00% | NULL | NULL |
| 0  | NULL | *NULL* | NULL | NULL | NULL | NULL | NULL | NULL | 0 | 0.00% | NULL | NULL |
| 0  | NULL | *NULL* | NULL | NULL | NULL | NULL | NULL | NULL | 0 | 0.00% | NULL | NULL |



### Explain信息解读


## 参数比较包含隐式转换，无法使用索引

* **Item:**  ARG.003

* **Severity:**  L4

* **Content:**  t表中列name的定义是 varchar(20) 而不是 int。




$ ./bin/soar -query="select id,name from t where name = 123"  -test-dsn="root:@tcp(127.0.0.1:4000)/soar" -online-dsn="root:@tcp(127.0.0.1:4000)/soar"
# Query: E3B4FC56CC28E1C5

★ ★ ★ ★ ★ 100分

```sql

SELECT  
  id, name  
FROM  
  t  
WHERE  
  name  = 123
```

## OK