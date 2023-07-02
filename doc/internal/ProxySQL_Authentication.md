# Sequence Diagrams during authentication

The initial handshake is what described in the MySQL protocol.

```mermaid
---
title: Initial (not complete) Handshake 
---

sequenceDiagram
autonumber
participant C as Client
participant S as Session
S ->> C: InitialHandshake
opt SSL handshake
C ->> S: SSL request
C -> S: SSL handshake
end
C ->> S: HandshakeResponse
Note over C, S: What happens next is described in<br/>"flowchart after Initial Handshake"
```

1. implemented in `MySQL_Protocol::generate_pkt_initial_handshake()`
2. performed by the client
3. implemented in `handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE()` and `MySQL_Protocol::process_pkt_handshake_response()` 
4. performed by the client


## flowchart after Initial Handshake

After the Initial Handshake (described above) different sequences are possible. In here we can distinguish sequences based on the authentication plugin based by ProxySQL and the Client, resulting in 4 different sequences.

```mermaid
flowchart
A[Initial Handshake]
PAM{proxysql auth}
CAM1{client auth}
CAM2{client auth}
A --> PAM
SA[Sequence A]
SB[Sequence B]
SC[Sequence C]
SD[Sequence D]
PAM -->|mysql_native_password| CAM1
PAM -->|caching_sha2_password| CAM2
CAM1 -->|mysql_native_password| SA
CAM1 -->|caching_sha2_password| SB
CAM2 -->|mysql_native_password| SC
CAM2 -->|caching_sha2_password| SD

```


## Sequence A
ProxySQL: mysql_native_password
<br/>
client: mysql_native_password
<br/>
```mermaid
---
title: "Sequence A"
---
sequenceDiagram
autonumber
participant C as Client
participant S as Session
S ->> C: InitialHandshake
opt SSL handshake
C ->> S: SSL request
C -> S: SSL handshake
end
C ->> S: HandshakeResponse
alt valid credential
S ->> C: OK
else invalid credential
S ->> C: Error
end
```

<br/>

## Sequence B
ProxySQL: mysql_native_password
<br/>
client: caching_sha2_password
<br/>

When ProxySQL uses `mysql_native_password` but client uses `caching_sha2_password` , ProxySQL askes the client to switch to `mysql_native_password`.
The client can either:
* perform the authentication using `mysql_native_password` (point 6)
* disconnect (point 9)

```mermaid
---
title: "Sequence B"
---
sequenceDiagram
autonumber
participant C as Client
participant S as Session
S ->> C: InitialHandshake
opt SSL handshake
C ->> S: SSL request
C -> S: SSL handshake
end
C ->> S: HandshakeResponse
S ->> C: Authentication method switch <br/> to mysql_native_password
alt client agrees to switch
C ->> S: hash (password + scramble)
alt valid credential
S ->> C: OK
else invalid credential
S ->> C: Error
end
else
C --x S: disconnect
end
```

<br/>
<br/>

## State Diagram of MySQL_Session during authentication

When a new session is created the status `session_status___NONE` is assigned by default.  
After the initial handshake is sent, the status is set to `CONNECTING_CLIENT`.  
The status is finally changed to `WAITING_CLIENT_DATA` if the authentication is completed. If the authentication is not successful the session is simply destroyed.
<br/>
<br/>
```mermaid
---
title: MySQL_Session status during authentication
---
stateDiagram-v2
session_status___NONE --> CONNECTING_CLIENT CONNECTING_CLIENT --> WAITING_CLIENT_DATA
```

<br/>
<br/>

## Generic flowchart of authentication (without subgraphs)
```mermaid
flowchart
A["generate_pkt_initial_handshake()"]
A1["status=CONNECTING_CLIENT"]
B["get_pkts_from_client()"]
C{status}
C1{client_myds->DSS}
D["handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE()"]
A --> A1
A1 --> B
B --> C
C -->|CONNECTING_CLIENT| C1
C1 -->|STATE_SERVER_HANDSHAKE| D
C1 -->|STATE_SSL_INIT| D
E["handshake_response_return = process_pkt_handshake_response()"]
D --> E
F{"handshake_response_return"}
F1{"client_myds->auth_in_progress != 0"}
E --> F
F -->|false| F1
F1 -->|Yes| B
F2{"is_encrypted == false
&&
client_myds->encrypted == true"}
F3[Initialize SSL]
F1 -->|No| F2
F2 -->|Yes| F3
F3 --> B
F2 -->|No| W
G{correct session_type}
F -->|true| G
G -->|false| W
OK["status=WAITING_CLIENT_DATA"]
SOK["send OK to client"]
G -->|true| SOK
SOK --> OK
OK --> B
W[Disconnect]
```
<br/>

After the initial handshake is sent and , `status` is set to `CONNECTING_CLIENT`.  
The main routine in `MySQL_Session` is `handler()` , and one of the main function it calls is `get_pkts_from_client()`.  
As the name suggests, `get_pkts_from_client()` is responsible from retrieving packets sent by the client: then it performs actions based on `status`.  
During authentication only `status==CONNECTING_CLIENT` is relevant.  
If `status==CONNECTING_CLIENT` and `client_myds->DSS` (`client_myds` represents the Client `MySQL_Data_Stream` , and `DSS` respesents its status) is either `STATE_SERVER_HANDSHAKE` or `STATE_SSL_INIT` , then `handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE()` is executed.  
`handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE()` calls `process_pkt_handshake_response()` and performs actions based on its return code.

`process_pkt_handshake_response()` historically was responsible for only processing **HandshakeResponse** packet, but over time became more complex to also handle **SSL Handshake** , **Authentication method switch** , **Fast Authentication** and **Full Authentication** . The details of `process_pkt_handshake_response()` will be described in more detailed flowcharts and diagrams.  
For now it is worth to note that `process_pkt_handshake_response()` returns:
*  `true` when authentication succeeded
* `false` when authentication failed or it is not completed yet (other status variables needs to ne evaluated)

If `handshake_response_return`:
* `true` : if `session_type` is correct (for example, a user defined in `mysql_users` table is not trying to connect to Admin, or viceversa) , the authentication succeeded, an OK packet is sent to the client, and status is changed to `WAITING_CLIENT_DATA` 
* `false` :
    * if authentication is still in progress : continue
    * if SSL has been required: initialize SSL and: continue
    * else: wrong credentials, disconnect

Below is the same flowchart with subgraphs.



## Generic flowchart of authentication (with subgraphs)
```mermaid
flowchart
subgraph sub0 [" "]
A["generate_pkt_initial_handshake()"]
A1["status=CONNECTING_CLIENT"]
A --> A1
end
A1 --> sub1
subgraph sub1 ["get_pkts_from_client()"]
B["get_pkts_from_client()"]
C{status}
C1{client_myds->DSS}
B --> C
C -->|CONNECTING_CLIENT| C1
end
subgraph sub2 ["handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE()"]
D["handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE()"]
D --> E
E["handshake_response_return = process_pkt_handshake_response()"]
F{"handshake_response_return"}
F1{"client_myds->auth_in_progress != 0"}
E --> F
F -->|false| F1
F1 -->|Yes| B
F2{"is_encrypted == false
&&
client_myds->encrypted == true"}
F3[Initialize SSL]
F1 -->|No| F2
F2 -->|Yes| F3
F3 --> B
F2 -->|No| W
G{correct session_type}
F -->|true| G
G -->|false| W
W[Disconnect]
OK["status=WAITING_CLIENT_DATA"]
SOK["send OK to client"]
G -->|true| SOK
SOK --> OK
OK --> B
end
C1 -->|STATE_SERVER_HANDSHAKE| D
C1 -->|STATE_SSL_INIT| D
```

See description in previous flowchart.  


## Details about `MySQL_Protocol::process_pkt_handshake_response()`

Because `MySQL_Protocol::process_pkt_handshake_response()` grew over time and was then split into multiple methods, variables are passed to and from methods using 2 objects of the following 2 classes:

```mermaid
---
title: classes used by authentication functions
---
classDiagram
class MyProt_tmp_auth_vars{
    unsigned char *user
    char *db
    char *db_tmp
    unsigned char *pass
    char *password
    unsigned char *auth_plugin
    void *sha1_pass=NULL
    unsigned char *_ptr
    unsigned int charset
    uint32_t  capabilities
    uint32_t  max_pkt
    uint32_t  pass_len
    bool use_ssl
    enum proxysql_session_type session_type
}
class MyProt_tmp_auth_attrs {
    char *default_schema
    char *attributes
    int default_hostgroup
    int max_connections
    bool schema_locked
    bool transaction_persistent
    bool fast_forward
    bool _ret_use_ssl
}
```

### Flowchart of `MySQL_Protocol::process_pkt_handshake_response()`


```mermaid
flowchart
A[Read packet header]
B{"username is
already known
from aprevious
packet"}
PPHR_1{"rc =
PPHR_1()"}
DOAUTH[__do_auth]
EXITDOAUTH[__exit_do_auth]
EXIT[__exit_process_pkt_handshake_response]
ASSERT["assert(0)"]
A --> B
PPHR_2{"bool_rc =
PPHR_2()"}
subgraph 16

B -->|Yes| PPHR_1
PPHR_1 -->|default| ASSERT
B -->|No| PPHR_2
PPHR_2 -->|true| PPHR_3["PPHR_3()"]
end

PPHR_1 -->|1| EXIT
PPHR_1 -->|2| DOAUTH


PPHR_2 -->|false| EXIT

SAPID{sent_auth_plugin_id}
PPHR_3 --> SAPID
APID1{auth_plugin_id}
APID2{auth_plugin_id}
SAPID -->|AUTH_MYSQL_NATIVE_PASSWORD| APID1
SAPID -->|AUTH_MYSQL_CACHING_SHA2_PASSWORD| APID2


subgraph 13
APID1_-1{"bool_rc =
PPHR_4auth0()"}
APID1 -->|AUTH_UNKNOWN_PLUGIN| APID1_-1
APID1_0{"bool_rc =
PPHR_4auth1()"}
APID1 -->|AUTH_MYSQL_NATIVE_PASSWORD| APID1_0
APID1 -->|default| a2["assert(0)"]
end
APID1_-1 -->|false| EXIT
APID1_-1 -->|true| DOAUTH
APID1_0 -->|false| EXIT
APID1_0 -->|true| DOAUTH
APID1 -->|AUTH_MYSQL_CLEAR_PASSWORD| DOAUTH


APID2_0{"bool_rc =
PPHR_4auth0()"}

subgraph 14
APID2 -->|AUTH_UNKNOWN_PLUGIN| APID2_0
APID2 -->|AUTH_MYSQL_NATIVE_PASSWORD| APID2_0
APID2_sha2_a{auth_in_progress}
APID2_sha2_s{switching_auth_stage}
APID2 -->|AUTH_MYSQL_CACHING_SHA2_PASSWORD| APID2_sha2_a
APID2_sha2_a -->|0| APID2_sha2_s
APID2_sha2_a -->|default| a3["assert(0)"]
end
APID2 -->|AUTH_MYSQL_CLEAR_PASSWORD| DOAUTH
APID2_0 -->|true| DOAUTH
APID2_0 -->|false| EXIT
APID2_sha2_s -->|0| DOAUTH
APID2_sha2_s -->|default| a3

getCharset[get client charset/collation]
DOAUTH --> getCharset



subgraph 18 [" "]
gcv{valid collation}
getCharset --> gcv

sessionType1{session_type}
gcv -->|true| sessionType1
P1Click["password = GloClickHouseAuth->lookup()"]
P1MySQL["password = GloMyAuth->lookup()"]


sessionType1 -->|PROXYSQL_SESSION_CLICKHOUSE| P1Click
sessionType1 -->|default| P1MySQL
P1NULL{password == NULL}
P1Click --> P1NULL
P1MySQL --> P1NULL
end
gcv -->|false| EXITDOAUTH


sessionType2{session_type}
PPHR_5passwordFalse_0["
PPHR_5passwordFalse_0()

If username and password are the one used
by MySQL_Monitor, set ret=true .  
This allows connections from MySQL Monitor module.
"]

P1NULL -->|true| sessionType2
subgraph sub2

sessionType2 -->|PROXYSQL_SESSION_ADMIN| PPHR_5passwordFalse_0
sessionType2 -->|PROXYSQL_SESSION_STATS| PPHR_5passwordFalse_0

APID3{auth_plugin_id}
sessionType2 -->|default| APID3
PPHR_5passwordFalse_auth2["
PPHR_5passwordFalse_auth2()

Relevant only for LDAP Authentication.
TODO: Document it properly.
"]
APID3 -->|AUTH_MYSQL_CLEAR_PASSWORD| PPHR_5passwordFalse_auth2


end
PPHR_5passwordFalse_0 --> EXITDOAUTH
APID3 -->|default| EXITDOAUTH
PPHR_5passwordFalse_auth2 --> EXITDOAUTH

PPHR_5passwordTrue["PPHR_5passwordTrue()

Assignes all the variables retrieved
from the Authentication module to
related MySQL_Session object.
"]
P1NULL -->|false| PPHR_5passwordTrue
EP{"password == ''"}
PPHR_5passwordTrue --> EP
EP -->|true| RET1[ret=true]
RET1 --> EXITDOAUTH
APID_SHA2_PASS{"auth_plugin_id ==
AUTH_MYSQL_CACHING_SHA2_PASSWORD
&&
password in SHA2 format"}
EP -->|false| APID_SHA2_PASS

subgraph sub3
APID_SHA2_PASS -->|false| PASSCT
APID_SHA2_PASS -->|true| PPHR_sha2full1["PPHR_sha2full(AUTH_MYSQL_CACHING_SHA2_PASSWORD)"]
end

PPHR_sha2full1 --> EXITDOAUTH
PASSCT{"password in
cleartext format"}

subgraph sub4
PASSCT -->|true| APID4{auth_plugin_id}
APID4 -->|AUTH_MYSQL_NATIVE_PASSWORD| SM{scrambles match}

SM -->|true| RET2["ret=true"]
APID4 -->|AUTH_MYSQL_CLEAR_PASSWORD| PM{passwords match}

PM -->|true| RET3["ret=true"]
PPHR_6auth2["PPHR_6auth2()

Performs a fast authentication using
caching_sha2_password. Fast authentication
means that we already have the password in
clear text and we can compare the hash of
password and scramble generated by the client.

Sets ret=true if the hashes match.
"]
APID4 -->|AUTH_MYSQL_CACHING_SHA2_PASSWORD| PPHR_6auth2
PPHR_6auth2 --> RET4{ret == true}
RET4 -->|true| SFAS["send fast_auth_success"]
end

SM -->|false| EXITDOAUTH
PM -->|false| EXITDOAUTH
RET4 -->|false| EXITDOAUTH
SFAS --> EXITDOAUTH
RET2 --> EXITDOAUTH
RET3 --> EXITDOAUTH


PASS_SHA1{"password in
sha1 format"}
PASSCT -->|false| PASS_SHA1
subgraph sub5

PASS_SHA1 -->|true| APID5{auth_plugin_id}
PPHR_7auth1["PPHR_7auth1()

Used in mysql_native_password.
If SHA1 of password and scramble match:
ret = true
If sha1 wasn't available, save it in GloMyAuth
"]
PPHR_7auth2["PPHR_7auth2()

Used in mysql_clear_password and when
only double SHA1 is known.
If double SHA1 of password match:
ret = true
If sha1 wasn't available, save it in GloMyAuth
"]
APID5 -->|AUTH_MYSQL_NATIVE_PASSWORD| PPHR_7auth1
APID5 -->|AUTH_MYSQL_CLEAR_PASSWORD| PPHR_7auth2
APID5 -->|AUTH_MYSQL_CACHING_SHA2_PASSWORD| PPHR_sha2full2["PPHR_sha2full(AUTH_MYSQL_NATIVE_PASSWORD)"]
end

PASS_SHA1 -->|false| EXITDOAUTH
PPHR_7auth1 --> EXITDOAUTH
PPHR_7auth2 --> EXITDOAUTH
PPHR_sha2full2 --> EXITDOAUTH

EXITDOAUTH --> PPHR_SetConnAttrs["PPHR_SetConnAttrs()"]
v1use_ssl{vars1.use_ssl}
PPHR_SetConnAttrs --> v1use_ssl
v1use_ssl -->|true| RET5[ret=true]
RET5 --> EXIT
rc5{ret}
v1use_ssl -->|false| rc5
subgraph subrc5
rc5 -->|true| SETCC[Set correct credentials in userinfo]
rc5 -->|false| SETEC[Set empty credentials in userinfo]
SETCC --> CH["compute_hash()"]
SETEC --> CH["compute_hash()"]
end

CH --> EXIT
EXIT --> Cleanup["Perform cleanup of temporary variables"]
Cleanup --> rc6{ret}
rc6 -->|true| verify_user_attributes["verify_user_attributes()"]
rc6 -->|false| RetRet["return ret"]
verify_user_attributes --> RetRet
```


### Flowchart of `MySQL_Protocol::PPHR_1()`


```mermaid
flowchart
SAS1{switching_auth_stage}
SAS1 -->|1| sas2["switching_auth_stage = 2
It means: stage1 (used by MYSQL_NATIVE_PASSWORD)
is completed"]
SAS1 -->|4| sas5["switching_auth_stage = 5
It means: stage4 (used by CACHING_SHA2_PASSWORD)
is completed"]
AIP["auth_in_progress = 0

This signals that the authorization should complete now
"]
SAS1 --> AIP
sas2 --> AIP
sas5 --> AIP
PL{packet len}
AIP --> PL
PL -->|5| cd["Client disconnected 
without performing the switch
"] --> ret1[return 1]
APID["
We previously stored the auth_plugin_id in myds->switching_auth_type<br/>
auth_plugin_id = myds->switching_auth_type
"]
PL --> APID
auth_plugin_id{auth_plugin_id}
APID --> auth_plugin_id
auth_plugin_id -->|AUTH_MYSQL_NATIVE_PASSWORD| PL1[password = the rest of the packet]
auth_plugin_id -->|default| PL2[password = NULL terminated C string]
Con1["Retrieve previously stored variables
from myds , userinfo, and myconn "]
PL1 --> Con1
PL2 --> Con1
Con1 --> ret2[return 2]
```


### Flowchart of `MySQL_Protocol::PPHR_2()`

This method is the one responsible for parsing the very first Handshake Response from the client.

```mermaid
flowchart
A["Parse capabilities and max_allowed_pkt,
and save them in myconn->options
"]
STS{"encrypted == false
&&
packet_length == header + 32
"}
A --> STS
SV["This is an SSLRequest.
Client wants to switch to SSL

encrypted = true
use_ssl = true
ret = false
"]
STS -->|Yes| SV
SV --> RF["return false"]
cv{charset == 0}
STS -->|No| cv
SDC["set charset = default SQL_CHARACTER_SET
See bug #810"]
cv -->|Yes| SDC
GetUser["Parse username"]
cv -->|No| GetUser
SDC --> GetUser
GetUser --> GetPass["Parse authentication data"] -- on error --> E1["ret = false"] --> RF
GetPass --> GetDB["Parse database name"]
GetDB --> GetAuthPlugin["Parse authentication plugin"]
GetAuthPlugin --> RT["return true"]
```

### Flowchart of `MySQL_Protocol::PPHR_3()`

This method is the one responsible for detecting the authentication plugin to use .  
It opererates on three variables with similar names:
* `vars1.auth_plugin` : the plugin that the client wish to use
* `sent_auth_plugin_id` : member of `MySQL_Protocol` . It defines which default plugin was sent by ProxySQL to the client
* `auth_plugin_id` : member of `MySQL_Protocol` . It defines which plugin is being used

It is worth noticing that any unknown plugin is threated as unknown.  
Also, if ProxySQL sends `mysql_native_password` and the client sends `caching_sha2_password` , ProxySQL will threat it as unknown, then forcing the client to switch to `mysql_native_password`.


```mermaid
flowchart
AP1{"vars1.auth_plugin
==
NULL"}
B["vars1.auth_plugin = mysql_native_password
auth_plugin_id = AUTH_MYSQL_NATIVE_PASSWORD
"]
AP1 -->|Yes| B
B -->APID
AP1 -->|No| APID
APID{"auth_plugin_id
==
AUTH_UNKNOWN_PLUGIN"}
APID -->|No| return
AP2{"vars1.auth_plugin"}
APID -->|Yes| AP2
AP2 -->|mysql_native_password| S1["auth_plugin_id =
AUTH_MYSQL_NATIVE_PASSWORD"] 
AP2 -->|mysql_clear_password| S2["auth_plugin_id =
AUTH_MYSQL_CLEAR_PASSWORD"] 
SAPID{sent_auth_plugin_id}
AP2 -->|caching_sha2_password| SAPID
SAPID -->|AUTH_MYSQL_NATIVE_PASSWORD| S3["auth_plugin_id =
AUTH_UNKNOWN_PLUGIN"]
SAPID -->|AUTH_MYSQL_CACHING_SHA2_PASSWORD| S4["auth_plugin_id =
AUTH_MYSQL_CACHING_SHA2_PASSWORD"]
S1 --> return
S2 --> return
S3 --> return
S4 --> return
```


### Flowchart of `MySQL_Protocol::PPHR_4auth0()`

TODO


### Flowchart of `MySQL_Protocol::PPHR_4auth1()`

This method is the one responsible for determining if ProxySQL can switch authentication to `mysql_clear_password` for LDAP plugin.  
At its core, it verify that the requested user doesn't exist.

```mermaid
---
title: MySQL_Protocol::PPHR_4auth1()
---
flowchart
A{"LDAP
Authentication
enabled"}
SAS{"switching_auth_stage
==
0"}
UE{"
user_exists
=
GloMyAuth->exists
"}
A -->|Yes| SAS
A -->|No| RT
SAS -->|Yes| UE
SAS -->|No| RT
UE -->|No| RT
C1["
switching_auth_type = AUTH_MYSQL_CLEAR_PASSWORD
switching_auth_stage = 1
auth_in_progress = 1
"]
UE --> C1
C1 --> G["generate_pkt_auth_switch_request()"]
G --> RRF[ret = false]
RRF --> RF[return false]
RT[return true]
```


### `MySQL_Protocol::PPHR_5passwordTrue()`

Give all the attributes received from the Authentication module in `MyProt_tmp_auth_attrs& attr1` , `MySQL_Protocol::PPHR_5passwordTrue()` is responsible for assigning all the variables to related `MySQL_Session` object.


### `MySQL_Protocol::PPHR_5passwordFalse_0()`

If `username` and `password` are the one used by `MySQL_Monitor` , set `ret=true` .  
This allows connections from MySQL Monitor module.


### `MySQL_Protocol::PPHR_5passwordFalse_auth2()`

TODO: document

### `MySQL_Protocol::PPHR_6auth2()`

Documented in the flowchart


### `MySQL_Protocol::PPHR_7auth1()`

Used for `mysql_native_password` authentication.
If SHA1 of password and scramble match, then sets `ret=true`.  
If sha1 wasn't previous available, save it in `GloMyAuth` calling `GloMyAuth->set_SHA1()` .
Also set it in `userinfo->sha1_pass`.

### `MySQL_Protocol::PPHR_7auth2()`

Used for `mysql_clear_password` authentication when password is saved as double SHA1.
If the double SHA1 password match then sets `ret=true`.  
If sha1 wasn't previous available, save it in `GloMyAuth` calling `GloMyAuth->set_SHA1()` .
Also set it in `userinfo->sha1_pass`.

### Flowchart of `MySQL_Protocol::PPHR_sha2full()`

This method is the one responsible to perform (start, or continue/complete) `caching_sha2_password` full authentication.  
If `switching_auth_stage`:
* 0 : set it to 4, and **start** full authentication
* 5 : **continue/complete** full authentication

This function receives in `passformat` the format of the known password.


```mermaid
---
title: MySQL_Protocol::PPHR_sha2full()
---
flowchart
return
SAS{switching_auth_stage}
GOBP["generate_one_byte_pkt(perform_full_authentication)"]
SV["switching_auth_type = auth_plugin_id
switching_auth_stage = 4
auth_in_progress = 1
"]
SAS -->|0| GOBP --> SV --> return
PF1{"passformat"}
SAS -->|5| PF1
SAS -->|default| a1["assert(0)"]
B5N1[Generate double SHA1]
B5N2{"double
SHA1s
match"}
PF1 -->|AUTH_MYSQL_NATIVE_PASSWORD| B5N1 --> B5N2

B5C1["
Extract salt and rounds
of SHA256() from
encoded hashed password
"]
B5C2["
Run SHA256()
rounds times on
cleartext password"]
B5C3{"encoded hashed
passwords match"}
PF1 -->|AUTH_MYSQL_CACHING_SHA2_PASSWORD| B5C1 --> B5C2 --> B5C3
PF1 -->|default| a1
SRT["ret = true"]
B5N2 -->|No| RT
B5N2 -->|Yes| SRT
B5C3 -->|Yes| SRT
RT{ret}
SRT --> RT
B5C3 -->|No| RT
SCT["GloMyAuth->set_clear_text_password()

Save (cache) clear text password in
order to perform fast authentication.
This is exactly what 'caching' means
in caching_sha2_password
"]
RT -->|false| return
RT -->|true| SCT
SCT --> return
```
