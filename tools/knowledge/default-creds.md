# 常见组件默认凭证表（入口/内网管理端口逐个试，题目 hint 常暗示产品名相关口令）

## 中间件/管理台
| 组件 | 端口 | 凭证 |
|---|---|---|
| Tomcat Manager | 8080 | tomcat:tomcat / admin:admin / role1:role1（manager/html 需 roles） |
| Jenkins | 8080 | admin:admin（初始密码在 ~/.jenkins/secrets/initialAdminPassword） |
| WebLogic | 7001 | weblogic:welcome1 / weblogic:weblogic |
| JBoss | 8080 | admin:admin |
| RabbitMQ Mgmt | 15672 | guest:guest（仅 localhost，SSRF 可打） |
| ActiveMQ | 8161 | admin:admin |
| Zabbix | 80/10051 | Admin:zabbix / guest:空 |
| Grafana | 3000 | admin:admin / admin:prom-operator |
| Kibana | 5601 | elastic:changeme |
| Nexus | 8081 | admin:admin123 |
| GitLab | 80/443 | root:5iveL!fe |
| Harbor | 443 | admin:Harbor12345 |
| nacos | 8848 | nacos:nacos（配合未授权 UEDET/任意用户注册更常见） |
| Apisix/Kong 网关管理面 | 9080/8001 | admin:admin / anon |

## 数据库/缓存
| 组件 | 端口 | 凭证/要点 |
|---|---|---|
| MySQL | 3306 | root:root / root:空 / root:mysql |
| PostgreSQL | 5432 | postgres:postgres / postgres:123456 |
| MongoDB | 27017 | 无认证常见（mongosh 直连）；admin:admin |
| Redis | 6379 | 无认证最常见；有密码试 root/123456 |
| Elasticsearch | 9200 | 无认证常见；elastic:elastic / elastic:changeme |
| Memcached | 11211 | 无认证 |
| ClickHouse | 8123 | default:空 |
| MinIO | 9000 | minioadmin:minioadmin |
| etcd | 2379 | 无认证常见 |

## Linux/网络设备
- SSH: root:root / admin:admin / ubuntu:ubuntu + 产品名:产品名123
- products: admin:password / admin:admin@123 / Admin@123（国内设备常见）
- vue/react 前端接口登录：admin:123456 / test:123456 / guest:guest

## 打法纪律
1. 端口指纹 → 本表逐个试（脚本循环 curl，错提无罚但登录失败锁定要看响应）
2. 登录失败 ≠ 完：找注册接口/忘记密码/默认页信息泄露/弱 token（JWT none）
3. 命中立即记 HOSTS.md 台账（`- 主机 | 端口/服务 | 凭据(命中) | flag 状态`）
4. 内网横向时把入口站收集的凭据全量重放：`/opt/tools/creds_replay.sh <IP>`
