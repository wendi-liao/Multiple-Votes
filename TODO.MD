
目前规划：数据库内部结构由文曦来搞；剩下的由lwd来搞；
有**的都是文曦同学需要做的：

Voter - Registrar:
voter有多个votes，目前做的是把一个个vote拆分出来发给registra，VoterToRegistrar_Register_Message 结构不变。
但是这样做：原来有一个查找该voter是否投票过的方法，就不能这么用了。

*todo：数据库结构怎么规划？（我们可以讨论一下）
方案1：VoterToRegistrar_Register_Message 结构不变。每次给数据库传入单个vote（也许再加上vote的编号？），判断该投票者是否已经投了该票；
方案2：把所有票一次性传过来，那么VoterToRegistrar_Register_Message 结构要变。每次给数据库传入所有的votes，判断该投票者是否已经投了票；*

Voter - Tallyer
voter有多个votes，目前做的是把votes合并到一起发给Tallyer，
Tallyer在收到后，检查是否已经投过（看起来这个函数已经写好了？）。
最后需要将签名好的votes放入数据库中，结构是TallyertoWorld：
void TallyerClient::HandleTally中调用*db_driver->insert_vote(t2w_msg);* 需要改

Arbiter 
HandleAdjudicate内调用了：
*this->db_driver->insert_partial_decryption(partialRows);要改*原来是插入一个PartialDecryptionRow partial_decryption，现在要变成vectro<>（对应课上内容，每一个vector内的元素是图片中的一列）

Voter-Verify
*通过db_driver->all_votes()， VoteRow里面包含了每一个voter投的所有票（对应图中的一行），返回的是std::vector<VoteRow>，待修改*

*db_driver->all_partial_decryptions(); 待修改*
lwd的想法：db_driver->all_partial_decryptions(i), 加一个参数i，代表返回针对candidate i的投票结果。（也许名字也应该改成：db_driver->some_partial_decryptions(i)(bushi)）

这里和arbiter ’this->db_driver->insert_partial_decryption(partialRows);‘相互对应。返回的是就是vector<std::vector<PartialDecryptionRow>>
我们可以讨论一下有关这个结构，是否需要给std::vector<PartialDecryptionRow>建立一个struct？
(这里的代码部分lwd还没有改)