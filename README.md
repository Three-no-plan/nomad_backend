# `nomad_backend`

## 生成合约地址

### 方式

- SDK生成
- canister生成
- 收费的问题

### 一个canisters只生成一个BTC地址作为资金地址（初始化，写入info方法）

- 签名

	- 生成的时候直接签名消息
	- 获取的时候直接解析
	- 不需要额外存储链表

- 随机数

## deploy

### 输入（转账hex，token_name，num，target_volume）

### 根据info获取canister地址

- runes

	- 根据用户给的拆分utxo设置份数，例如1000份utxo

### 验证hex结构

- 解析hex交易结构

### 验证token

- 在索引canister中确定转账地址和数量的正确性，并记录相应的链表

### 根据随机数生成相应的contract address

### 生成相应的土狗token结构（contract address等等）

## mint

### 输入（转账raw哈希，contract_address）

### 根据contract_address获取token信息

### 解析哈希计算相应的份额

### type

- brc20

	- 根据索引canister获得transfer utxo的信息

- runes

	- 根据打款数量分配相应的runes token utxo

		- runes utxo的txid根据vout确定

### 生成签名，更新token的情况(进度，地址等)

### 输出（返款的PSBT数据，然后广播）

## refund

### 打错退回的方法

- 解析用户的hex检测是否在生成token的utxo列表，不在直接输出签名
- 直接返给打款者（默认第一个）
- 直接定义进输入中，返回给输入参数

### IDO退款方法（juicebox）

- 解析用户，检查是否在utxo列表，不在直接报错，在的话检查提交brc20的转账是否正确，然后进行BTC的返款
- 输入（contract address，打款的hex）

	- 因此可以不限定只有参与者能够获取返款 

## bonding curve

### deploy方法

### 原本的mint变成buy方法

### 原本的refund变成sell方法

### 合约数据

## SWAP

### DEPLOY

### LP

### BUY

### POOL

### SELL

### APY

