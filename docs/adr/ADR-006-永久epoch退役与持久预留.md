# ADR-006：永久 epoch 退役与持久预留

**状态：Accepted**

接收端以单调 `retired_through` 永久拒绝旧 epoch；Host 在开始会话前以跨进程锁、落盘和
原子替换持久预留下一个 epoch。有限退休环和随机派生 epoch 均不能提供长期防回滚保证。
无法预留唯一 epoch 时，Host 必须 fail-closed。
