---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults

layout: page
title: Benny Pinkas
---


| ![Profile picture](../bennyp.jpg){: width="350" } | **Benny Pinkas**<br> [Dept. of Computer Science](https://cs.biu.ac.il/) and Center for Research in Applied Cryptography and Cyber Security<br>[Bar Ilan University](https://biu.ac.il/en) <br> Email: my-first-name at pinkas.net<br> <br> **[[Linkedin]](https://www.linkedin.com/in/benny-pinkas-31336/) [[Google Scholar]](https://scholar.google.com/citations?user=tpMNnPwAAAAJ&hl=e) [[DBLP]](https://dblp.org/pid/31/1735.html)**|

---  
### Interests:  
- **I am interested in applied cryptography, computer security, blockchain security, and privacy, focusing on the design of efficient security systems based on sound assumptions and solid proofs.**  
- From September 2022 to October 2024 I worked at [Aptos Labs](https://aptoslabs.com/).
- During the 2011/2 academic year I was on sabbatical at [Google Research](http://www.google.com/). I previously worked at the [University of Haifa](https://cs.hevra.haifa.ac.il/index.php/en/), at HP Labs in Haifa and in Princeton, and at [STAR Labs](http://web.archive.org/web/*/http:/www.star-lab.com/), [Intertrust Technologies](http://www.intertrust.com/).  
- Before that I was a Ph.D. student of [Moni Naor](http://www.wisdom.weizmann.ac.il/%7Enaor)
at the [Weizmann Institute of Science](http://www.wisdom.weizmann.ac.il/).

---  
## Research highlights
I coauthored results which demonstrated that **secure multi-party computation (MPC)** can go beyond theoretical exploration and be used for implementing actual systems. These results include an early system that used secure computation for running [privacy preserving auctions](https://www.wisdom.weizmann.ac.il/~naor/PAPERS/nps.pdf) (1999); the [Fairplay system](../PAPERS/MNPS.pdf), which was the first system that enabled non-cryptographers to use
   generic secure computation (2004); the first design and implementation of [secure computation of the AES cipher](http://eprint.iacr.org/2009/314.pdf) (2009); and
   many other results on improving the generality and efficiency of secure computation. I also made many contributions to  efficient [Private Set Intersection -- PSI](https://en.wikipedia.org/wiki/Private_set_intersection), and focused on applying MPC for privacy preserving analytics of very large data. 


In addition to research on MPC, I often do research on other aspects of cyber security.

- In a [paper](../PAPERS/pwdweb.pdf) from 2002 we suggested to selectively combine **CAPTCHAs** in the user-authentication process, as an additional measure against dictionary attacks. (At the time of the publication of this work, CAPTCHAs were already known and were typically used for ensuring that only human users can receive specific services, but they were not used for protecting login attempts.) The solution that we proposed, which was new at the time, is now a common practice of almost all web services. 
- Our work on zero-knowledge proofs for solutions of **[Sudoku puzzles](PAPERS/sud_journal.pdf)** is widely used to demonstrate the concept of zero-knowledge proofs.
- Our work on **file deduplication** in [2010](./../PAPERS/hps.pdf) and [2011](http://eprint.iacr.org/2011/207) demonstrated the insecurity of deduplication in cloud storage.
- Following our work on the security of the **random number generators** of the [Linux](http://eprint.iacr.org/2006/086)  (in 2006), and of [Windows](http://eprint.iacr.org/2007/419) (in 2007) changes were applied to both systems to overcome the vulnerabilities that were discovered by us.
- A set of works on **network security** showed how different network fields, such as  [*IP ID*](https://www.usenix.org/system/files/sec19-klein.pdf), and the *flow label* in [IPv6](https://www.computer.org/csdl/proceedings-article/sp/2020/349700b594/1j2LgrHDR2o), enable to run a cryptanlysis of internal operating system functions in both Windows and Linux/Android, and even remotely break  KASLR security. As a result, both Microsoft and Linux twice applied patches that were pushed to all customers. 

---  
## Videos
Some [Youtube video](https://www.youtube.com/results?search_query=benny+pinkas), including a recent talk on [Distributed randomness using weighted VRFs](https://www.youtube.com/watch?v=-QrKQ0nIX4s), and old popular talks on [Oblivious RAM - ORAM](https://www.youtube.com/watch?v=3RWyVGwG9U8), [ZK for Sudoku](https://www.youtube.com/watch?v=_tGDoys_w5c), [Sigma protocols](https://www.youtube.com/watch?v=XT1Pad0DM24), and [Private Set Intersection - PSI](https://www.youtube.com/watch?v=iXopZ7A7dM0).

---  
## Publications  
**A Google Scholar [list of my papers](https://scholar.google.com/citations?user=tpMNnPwAAAAJ&hl=en) ranked by their citation count, and related statistics, are available at Google Scholar.**


- **Verifiable Secret Sharing Simplified**  
  Sourav Das, Zhuolun Xiang, Alin Tomescu, Alexander Spiegelman, Benny Pinkas, and Ling Ren
  Accepted to *IEEE S&P 2025*  
  [ePrint](https://eprint.iacr.org/2023/1196)

- **Distributed Randomness using Weighted VRFs**  
  Sourav Das, Benny Pinkas, Alin Tomescu, and Zhuolun Xiang  
 [ePrint](https://eprint.iacr.org/2024/198)

- **Distributing Keys and Random Secrets with Constant Complexity**  
  Benny Applebaum and Benny Pinkas  
  *Theory of Cryptography (TCC) 2024*  
  [ePrint](https://eprint.iacr.org/2024/876)


- **ScionFL: Efficient and Robust Secure Quantized Aggregation for Federated Learning**  
Yaniv Ben-Itzhak, Helen Möllering, Benny Pinkas, Thomas Schneider, Ajith Suresh, Oleksandr Tkachenko, Shay Vargaftik, Christian Weinert, Hossein Yalame, and Avishay Yanai  
*SaTML (IEEE Conference on Secure and Trustworthy Machine Learning) 2024*  
[arxiv](https://arxiv.org/abs/2210.07376)

- **Secure Statistical Analysis on Multiple Datasets: Join and Group-By**  
  Gilad Asharov, Koki Hamada, Ryo Kikuchi, Ariel Nof, Benny Pinkas, Junichi Tomida  
  *ACM CCS 2023*  
  [eprint](https://eprint.iacr.org/2024/141)

- **How to Recover a Secret with O(n) Additions**  
  Benny Applebaum, Oded Nir, Benny Pinkas  
  *CRYPTO 2023*  
  [eprint](https://eprint.iacr.org/2023/838)

- **Efficient Secure Three-Party Sorting with Applications to Data Analysis and Heavy Hitters**  
  Gilad Asharov, Koki Hamada, Dai Ikarashi, Ryo Kikuchi, Ariel Nof, Benny Pinkas, Katsumi Takahashi, and Junichi Tomida  
  *ACM CCS 2022*  
  [eprint](https://eprint.iacr.org/2022/1595)


- **GPU-accelerated PIR with Client-Independent Preprocessing for Large-Scale Applications**  
  Daniel Günther, Maurice Heymann, Benny Pinkas and Thomas Schneider  
  *Usenix Security Symposium 2022*  
  [full paper](https://eprint.iacr.org/2021/823) | [proceedings version and presentation](https://www.usenix.org/conference/usenixsecurity22/presentation/gunther)

- **UTT: Decentralized Ecash with Accountable Privacy**  
  Alin Tomescu, Adithya Bhat, Benny Applebaum, Ittai Abraham, Guy Gueta, Benny Pinkas, and Avishay Yanai  
  *The Science of Blockchain Conference 2023 (SBC'23)*  
  [paper](https://eprint.iacr.org/2022/452) | [project](https://research.vmware.com/projects/digital-cash-and-central-bank-digital-currencies)

- **Secure Graph Analysis at Scale**  
  Toshinori Araki, Jun Furukawa, Benny Pinkas, Kazuma Ohara, Hanan Rosemarin and Hikaru Tsuchida  
  *ACM CCS 2021*  
  [paper](https://dl.acm.org/doi/abs/10.1145/3460120.3484560)

- Gayathri Garimella, Benny Pinkas, Mike Rosulek, Ni Trieu, and Avishay Yanai  
  **Oblivious Key-Value Stores and Amplification for Private Set Intersection**  
  *Crypto 2021*  
  [paper](https://eprint.iacr.org/2021/883)

- Shahar Segal, Yossi Adi, Benny Pinkas, Carsten Baum, Chaya Ganesh, and Joseph Keshet  
  **Fairness in the Eyes of the Data: Certifying Machine-Learning Models**  
  *The Fourth AAAI/ACM Conference on Artificial Intelligence, Ethics, and Society (AIES), 2021*  
  [paper](https://arxiv.org/pdf/2009.01534.pdf)

- Daniel Günther, Marco Holz, Benjamin Judkewitz, Helen Möllering, Benny Pinkas, and Thomas Schneider  
  **PEM: Privacy-preserving Epidemiological Modeling**  
  [paper](https://eprint.iacr.org/2020/1546)

- Ittai Abraham, Benny Pinkas, and Avishay Yanai  
  **Blinder - Scalable, Robust Anonymous Committed Broadcast**  
  *ACM CCS 2020*  
  [paper](https://eprint.iacr.org/2020/248)

- Jonathan Berger, Amit Klein, and Benny Pinkas  
  **Flaw Label: Exploiting IPv6 Flow Label**  
  *IEEE S&P 2020*  
  [paper](https://www.computer.org/csdl/proceedings-article/sp/2020/349700b594/1j2LgrHDR2o)

- Alin Tomescu, Robert Chen, Yiming Zheng, Ittai Abraham, Benny Pinkas, Guy Golan Gueta, and Srinivas Devadas  
  **Towards Scalable Threshold Cryptosystems**  
  *IEEE S&P 2020*  
  [paper](https://research.vmware.com/files/attachments/0/0/0/0/0/9/7/dkg-sp2020.pdf)

- Benny Pinkas, Mike Rosulek, Ni Trieu, and Avishay Yanai  
  **PSI from PaXoS: Fast, Malicious Private Set Intersection**  
  *Eurocrypt 2020*  
  [eprint](https://eprint.iacr.org/2020/193)

- Moni Naor, Benny Pinkas, and Eyal Ronen  
  **How to (not) share a password: Privacy preserving protocols for finding heavy hitters with adversarial behavior**  
  *ACM CCS 2019*  
  [eprint](https://eprint.iacr.org/2018/003)

- Phillipp Schoppmann, Adria Gascon, Mariana Raykova, and Benny Pinkas  
  **Make Some ROOM for the Zeros: Data Sparsity in Secure Distributed Machine Learning**  
  *ACM CCS 2019*  
  [eprint](https://eprint.iacr.org/2019/281)

- Benny Pinkas, Mike Rosulek, Ni Trieu, and Avishay Yanai  
  **SpOT-Light: Lightweight Private Set Intersection from Sparse OT Extension**  
  *Crypto 2019*  
  [eprint](https://eprint.iacr.org/2019/634)

- Amit Klein and Benny Pinkas  
  **From IP ID to Device ID and KASLR Bypass**  
  *Usenix Security 2019*  
  [slides](https://www.usenix.org/sites/default/files/conference/protected-files/sec19_slides_klein.pdf)  
  [proceedings](https://www.usenix.org/system/files/sec19-klein.pdf)  
  [Windows vulnerability report](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0688), [Linux patch 1](https://github.com/torvalds/linux/commit/355b98553789b646ed97ad801a619ff898471b92), [Linux patch 2](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=df453700e8d81b1bdafdf684365ee2b9431fb702), [Linux patch 3](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=55f0fc7a02de8f12757f4937143d8d5091b2e40b)

- Benny Pinkas, Thomas Schneider, Oleksandr Tkachenko, and Avishay Yanai  
  **Efficient Circuit-based PSI with Linear Communication**  
  *Eurocrypt 2019*  
  [eprint](https://eprint.iacr.org/2019/241)

- Yehuda Lindell, Benny Pinkas, Nigel Smart, and Avishay Yanai  
  **Efficient Constant-Round Computation Combining BMR and SPDZ**  
  *Journal of Cryptology 2019*  
  [springer](https://link.springer.com/article/10.1007%2Fs00145-019-09322-2)  
  [eprint](https://eprint.iacr.org/2015/523)

- Amit Klein and Benny Pinkas  
  **DNS Cache-Based User Tracking**  
  *The Network and Distributed Security Symposium (NDSS) 2019*  
  [proceedings](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-4_Klein_paper.pdf)

- Koji Chida, Koki Hamada, Dai Ikarashi, Ryo Kikuchi, and Benny Pinkas  
  **High-Throughput Secure AES Computation**  
  *Workshop on Encrypted Computing and Applied Homomorphic Cryptography 2018*  
  [proceedings](http://delivery.acm.org/10.1145/3270000/3267977/p13-chida.pdf)

- Roi Inbar, Eran Omri, and Benny Pinkas  
  **Efficient Scalable Multiparty Private Set-Intersection via Garbled Bloom Filters**  
  *Security and Cryptography for Networks: SCN 2018*  
  [Springer](https://link.springer.com/chapter/10.1007%2F978-3-319-98113-0_13)

- Tore Fredriksen, Yehuda Lindell, Valery Osheter, and Benny Pinkas  
  **Fast Distributed RSA Key Generation for Semi-honest and Malicious Adversaries**  
  *Crypto 2018*  
  [eprint](https://eprint.iacr.org/2018/577)  
  [blog](https://medium.com/@benny.pinkas/fast-distributed-rsa-key-generation-against-malicious-adversaries-faaaab96821d)

- Yossi Adi, Carsten Baum, Moustapha Cissé, Benny Pinkas, and Joseph Keshet  
  **Turning Your Weakness Into a Strength: Watermarking Deep Neural Networks by Backdooring**  
  *Usenix Security 2018*  
  [arxiv](https://arxiv.org/abs/1802.04633)  
  [blog](https://medium.com/@carstenbaum/the-ubiquity-of-machine-learning-and-its-challenges-to-intellectual-property-dc38e7d66b05)  
  [slides and video](https://www.usenix.org/conference/usenixsecurity18/presentation/adi)

- Benny Pinkas, Thomas Schneider, Christian Weinert, and Udi Wieder  
  **Efficient Circuit-based PSI via Cuckoo Hashing**  
  *Eurocrypt 2018*  
  [eprint](https://eprint.iacr.org/2018/120)

- Yotam Harchol, Ittai Abraham and Benny Pinkas
  **Efficient Distributed SSH Key Management with Proactive RSA Threshold Signatures**
  *ACNS 2018*
  Available files: [eprint](https://eprint.iacr.org/2018/389)

- Tore Fredriksen, Benny Pinkas, and Avishay Yanai
  **Committed MPC - Maliciously Secure Multiparty Computation from Homomorphic Commitments**
  *PKC 2018*
  Available files: [eprint](https://eprint.iacr.org/2017/550)

- Benny Pinkas, Thomas Schneider and Michael Zohner
  **Scalable Private Set Intersection Based on OT Extension**
  *ACM Transactions on Privacy and Security, 21(2):7:1-7:35 (2018)*  
  Available files: [eprint](https://eprint.iacr.org/2016/930)

 - Vladimir Kolesnikov, Naor Matania, Benny Pinkas, Mike Rosulek, and Ni Trieu  
  **Practical Multi-party Private Set Intersection from Symmetric Key Techniques**  
  *ACM CCS 2017*  
  [eprint](https://eprint.iacr.org/2017/799)

- Eyal Kolman and Benny Pinkas  
  **Securely Computing a Ground Speed Model**  
  *ACM TIST 8(4), 2017*  
  [journal](https://dl.acm.org/citation.cfm?id=2998550)

- Niv Drucker, Shay Gueron, and Benny Pinkas  
  **Fast Secure Cloud Computations with a Trusted Proxy**  
  *IEEE Security and Privacy magazine 15(6): 61-67, 2017*

- Agnes Kiss, Jian Liu, Thomas Schneider, N. Asokan, and Benny Pinkas  
  **Private Set Intersection for Unequal Set Sizes with Mobile Applications**  
  *PoPETS 2017*  
  [eprint](https://eprint.iacr.org/2017/670)

- Sandeep Tamrakar, Jian Liu, Andrew Paverd, Jan-Erik Ekberg, Benny Pinkas, and N. Asokan  
  **The Circle Game: Scalable Private Membership Test Using Trusted Hardware**  
  *Asia CCS 2017* (received an [honorable mention](http://asiaccs2017.com/program/distinguished-papers/))  
  [arxiv](https://arxiv.org/abs/1606.01655)

- Ittai Abraham, Christofpher W. Fletcher, Kartik Nayak, Benny Pinkas, and Ling Ren  
  **An Oblivious RAM with Sub-logarithmic Bandwidth Blowup**  
  *PKC 2017*  
  Available files: [eprint](https://eprint.iacr.org/2016/849)

- David W. Archer, Dan Bogdanov, Benny Pinkas, and Pille Pullonen  
  **Maturity and Performance of Programmable Secure Computation**  
  *IEEE Security and Privacy Journal*, Vol. 14, Issue 5, 2016  
  Available files: [eprint](https://eprint.iacr.org/2015/1039)

- Michael Freedman, Carmit Hazay, Kobbi Nissim, and Benny Pinkas  
  **Efficient Set Intersection with Simulation-based Security**  
  *J. Cryptology* 29(1): 115-155 (2016)

- Shay Gueron, Yehuda Lindell, Ariel Nof, and Benny Pinkas  
  **Fast Garbling of Circuits Under Standard Assumptions**  
  *ACM CCS '2015* and *J. Cryptology* 31(3): 798-844 (2018)  
  Available files: [eprint](https://eprint.iacr.org/2015/751)

- Jian Liu, N. Asokan, and Benny Pinkas  
  **Secure Deduplication of Encrypted Data without Additional Independent Servers**  
  *ACM CCS '2015*  
  Available files: [eprint](https://eprint.iacr.org/2015/455)

- Yehuda Lindell, Benny Pinkas, Nigel Smart, and Avishay Yanai  
  **Efficient Constant Round Multi-party Computation Combining BMR and SPDZ**  
  *Crypto '2015*  
  Available files: [eprint](https://eprint.iacr.org/2015/523)

- Benny Pinkas, Thomas Schnedier, Gil Segev, and Michael Zohner  
  **Phasing: Private Set Intersection Using Permutation-based Hashing**  
  *Usenix Security '2015*  
  Available files: [eprint](https://eprint.iacr.org/2015/634)

- Benny Pinkas, Thomas Schnedier, and Michael Zohner  
  **Private Set Intersection based on OT Extension**  
  *Usenix Security '2014*  
  Available files: [eprint](https://eprint.iacr.org/2014/447)

- Benny Pinkas and Tzachy Reinman  
  **A Simple Recursive Tree Oblivious RAM**  
  Available files: [eprint](https://eprint.iacr.org/2014/418)

- Arash Afshar, Payman Mohassel, Benny Pinkas, and Ben Riva  
  **Non-Interactive Secure Computation Based on Cut-and-Choose**  
  *Eurocrypt '2014*  
  Available files: [slides](http://ec14.compute.dtu.dk/talks/24.pdf)

- Ayman Jarrous and Benny Pinkas  
  **Canon-MPC, a System for Casual Non-Interactive Secure Multi-party Computation using Native Client**  
  *Workshop on Privacy Enhancing Technologies (WPES) 2013*  
  Available files: [pdf](../../PAPERS/canon-mpc.pdf)

- Ayman Jarrous and Benny Pinkas  
  **Secure Computation of Functionalities based on Hamming Distance and its Application to Computing Document Similarity**  
  *International Journal of Applied Cryptography (IJACT)* 3(1): 21-45 (2013)  
  Available files: [pdf](../../PAPERS/jp13.pdf)

- Omer Berkman, Benny Pinkas, and Moti Yung  
  **Firm Grip Handshakes: a Tool for Bidirectional Vouching**  
  *CANS 2012, December 2012  
  Available files: [pdf](../../PAPERS/oreo.pdf)

- Shai Halevi, Danny Harnik, Benny Pinkas, and Alexandra Shulman-Peleg  
  **Proofs of Ownership in Remote Storage Systems**  
  *ACM CCS 2011*  
  Available files: [eprint](http://eprint.iacr.org/2011/207)

- Yehuda Lindell, Eli Oxman, and Benny Pinkas  
  **The IPS Compiler: Optimizations, Variants and Concrete Efficiency**  
  *Crypto 2011*  
  Available files: [eprint](http://eprint.iacr.org/2011/435)

- Shai Halevi, Yehuda Lindell, and Benny Pinkas  
  **Secure Computation on the Web: Computing without Simultaneous Interaction**  
  *Crypto 2011*  
  Available files: [eprint](http://eprint.iacr.org/2011/157)

- Yehuda Lindell and Benny Pinkas  
  **Secure Two-Party Computation via Cut-and-Choose Oblivious Transfer**  
  *Theory of Cryptography Conference (TCC) 2011*  
  Available files: [eprint](http://eprint.iacr.org/2010/284)

- Marc Fischlin, Benny Pinkas, Ahmad-Reza Sadeghi, Thomas Schneider, and Ivan Visconti  
  **Secure Set Intersection with Untrusted Hardware Tokens**  
  *CT-RSA 2011*  
  Available files: [pdf](http://thomaschneider.de/papers/FPSSV11.pdf)

- Benny Pinkas  
  **Traitor Tracing**  
  *Encyclopedia of Cryptography and Security (2nd Ed.), pp. 1313-1316, 2011*  
  [Link](http://www.springer.com/computer/security+and+cryptology/book/978-1-4419-5905-8)

- Danny Harnik, Benny Pinkas, and Alexandra Shulman-Peleg  
  **Side Channels in Cloud Services, the Case of Deduplication in Cloud Storage**  
  *IEEE Security and Privacy Magazine, special issue of Cloud Security, Vol. 8, No. 2, pp. 40-47, 2010*  
  Available files: [Older version of paper](../../PAPERS/hps.pdf)

- Moni Naor and Benny Pinkas  
  **Efficient Trace and Revoke Schemes**  
  *International Journal of Information Security, Springer-Verlag, Vol. 9, No. 6, pp. 40-47, 2010*

- Benny Pinkas and Tzachy Reinman  
  **Oblivious RAM Revisited**  
  *Crypto 2010*  
  Available files: [eprint](http://eprint.iacr.org/2010/366)

- Mark Manulis, Benny Pinkas, and Bertram Poettering  
  **Privacy-Preserving Group Discovery with Linear Complexity**  
  *ACNS 2010*  

- Margarita Osadchy, Benny Pinkas, Ayman Jarrous, and Boaz Moskovich  
  **SCiFI - A System for Secure Face Identification**  
  **(Received the [best paper award](http://oakland31.cs.virginia.edu/awards.html))**  
  *IEEE Symposium on Security & Privacy (SP) 2010*  
  Available files: [pdf](../PAPERS/scifi.pdf), [project and code](http://www.cs.haifa.ac.il/scifi)

- Gagan Aggarwal, Nina Mishra, and Benny Pinkas  
  **Secure Computation of the Median (and Other Elements of Specified Ranks)**  
  *Journal of Cryptology*, Vol. 23, No. 3, pp. 373-401. Online since February 05, 2010  
  Available files: [Springer](http://www.springerlink.com/content/f1066606k7118863/)

- Benny Pinkas, Thomas Schneider, Nigel P. Smart, and Stephen C. Williams  
  **Secure Two-Party Computation is Practical**  
  *ASIACRYPT 2009*  
  Available files: [pdf](http://eprint.iacr.org/2009/314.pdf)

- Ayman Jarrous and Benny Pinkas  
  **Secure Hamming Distance Based Computation and its Applications**  
  **(Best student paper award!)**  
  *ACNS 2009*  
  Available files: [pdf](../PAPERS/acns09.pdf)

- Danny Bickson, Tzachi Reinman, Danny Dolev, and Benny Pinkas  
  **Peer-to-Peer Secure Multi-party Numerical Computation Facing Malicious Adversaries**  
  *Peer-to-Peer Networking and Applications (PPNA) journal*, Springer, May 2009  
  Available files: [pdf](http://arxiv.org/abs/0901.2689)

- Y. Lindell and B. Pinkas  
  **Secure Multiparty Computation for Privacy-Preserving Data Mining**  
  *Journal of Privacy and Confidentiality*, Vol. 1, No. 1, pp. 59-98, 2009  
  Available files: [journal](http://repository.cmu.edu/jpc/vol1/iss1/5/), [pdf](http://repository.cmu.edu/cgi/viewcontent.cgi?article=1004&context=jpc)

- Y. Lindell and B. Pinkas  
  **A Proof of Yao's Protocol for Secure Two-Party Computation**  
  *Journal of Cryptology*, 22(2):161-188, 2009  
  Cryptology ePrint Archive: Report 2004/175 (also appeared in ECCC)  
  Available files: [pdf](http://eprint.iacr.org/2004/175.pdf), [ps](http://eprint.iacr.org/2004/175.ps)

- Assaf Ben-David, Noam Nisan, and Benny Pinkas  
  **FairplayMP - A System for Secure Multi-Party Computation**  
  *ACM Computer and Communications Security Conference (ACM CCS) 2008*  
  Available files: [pdf](http://www.cs.huji.ac.il/project/Fairplay/FairplayMP/FairplayMP.pdf), [website](http://www.cs.huji.ac.il/project/Fairplay/fairplayMP.html)

- Yehuda Lindell, Benny Pinkas, and Nigel Smart  
  **Implementing Two-Party Computation Efficiently with Security Against Malicious Adversaries**  
  *Conference on Security and Cryptography for Networks (SCN) 2008*  
  Available files: [pdf](http://www.cs.biu.ac.il/~lindell/../PAPERS/MPCimplement.pdf)

- D. Bickson, D. Dolev, G. Bezman, and B. Pinkas  
  **Secure Multi-Party Peer-to-Peer Numerical Computation**  
  *Proceedings of the 8th IEEE Peer-to-Peer Computing (P2P'08), 2008*
  Available files: [pdf](http://www.cs.huji.ac.il/~daniel51/bickson-smpc-p2p08.pdf)

- Leo Dorrendorf, Zvi Gutterman, and Benny Pinkas  
  **Cryptanalysis of the Windows Random Number Generator**  
  *ACM Computer and Communications Security Conference (ACM CCS) 2007*  
  Full version in ACM Transactions on Information and System Security (TISSEC), 13(1), 2009  
  Available files: [eprint](http://eprint.iacr.org/2007/419)  
  This paper received some publicity in the **press** (see [Slashdot](http://it.slashdot.org/article.pl?sid=07/11/12/1528211), [Computerworld](http://computerworld.com/action/article.do?command=printArticleBasic&articleId=9047179), [The Register](http://www.theregister.co.uk/2007/11/13/windows_random_number_gen_flawed))  
  See also Microsoft's confirmation of a similar problem in Windows XP: [Computerworld](http://www.computerworld.com/action/article.do?command=viewArticleBasic&articleId=9048438), [Slashdot](http://it.slashdot.org/article.pl?sid=07/11/22/040221), [The Register](http://www.theregister.co.uk/2007/11/23/win_xp_random_bug/)

- Ronen Gradwohl, Moni Naor, Benny Pinkas, and Guy Rothblum  
  **Cryptographic and Physical Zero-Knowledge Proof Systems for Solutions of Sudoku Puzzles**  
  *Proc. of *Fun with Algorithms 2007*, LNCS 4475, Springer-Verlag, pp. 166-182, June 2007  
  Full version in Theory of Computing Systems, Springer, Vol. 44, No. 2, pp. 245-268, February 2009  
  Available files: [proceedings version](PAPERS/sud_proc.pdf), [full version](PAPERS/sud_journal.pdf), [journal version](http://www.springerlink.com/content/w5534381621tp331/)

- Y. Lindell and B. Pinkas  
  **An Efficient Protocol for Secure Two-Party Computation in the Presence of Malicious Adversaries**  
  *Eurocrypt 2007*  
  Available files: [pdf](malicious.pdf)

- Z. Gutterman, B. Pinkas, and T. Reinman  
  **Analysis of the Linux Random Number Generator**  
  *IEEE Symposium on Security and Privacy (SP) 2006*  
  Available files: [eprint](http://eprint.iacr.org/2006/086)

- M. Naor and B. Pinkas  
  **Oblivious Polynomial Evaluation**  
  *Siam Journal on Computing*, Vol. 35, No. 5, 2006  
  Available files: [SpringerLink](http://www.springerlink.com/index/10.1007/s00145-004-0102-6)

- M. Naor and B. Pinkas  
  **Computationally Secure Oblivious Transfer**  
  *Journal of Cryptology*, Vol. 18, No. 1, 2005  
  Available files: [SpringerLink](http://www.springerlink.com/index/10.1007/s00145-004-0102-6)

- M. Freedman, Y. Ishai, B. Pinkas, and O. Reingold  
  **Keyword Search and Oblivious Pseudorandom Functions**  
  *Theory of Cryptography Conference (TCC '05) 2005*  
  Available files: [pdf](../PAPERS/FIPR.pdf), [ps](../PAPERS/FIPR.ps)

- D. Malkhi, N. Nisan, B. Pinkas, and Y. Sella  
  **Fairplay - A Secure Two-Party Computation System**  
  **(Best student paper award!)**  
  *Usenix Security 2004, August 9-13, 2004*  
  Available files: [pdf](../PAPERS/MNPS.pdf)


- M. Freedman, K. Nissim and B. Pinkas  
**Efficient Private Matching and Set Intersection**  
*Advances in Cryptology – Eurocrypt '2004 Proceedings*, LNCS 3027, Springer-Verlag, pp. 1-19, May 2004.  
Available files: [pdf](../PAPERS/FNP04.pdf)


- G. Aggarwal, N. Mishra and B. Pinkas  
**Secure Computation of the K'th-ranked Element**  
*Advances in Cryptology – Eurocrypt '2004 Proceedings*, LNCS 3027, Springer-Verlag, pp. 40-55, May 2004.  
Available files: [pdf](../PAPERS/ANP04.pdf)


- E.-J. Goh, D. Boneh, P. Golle and B. Pinkas  
**The Design and Implementation of Protocol-Based Hidden Key Recovery**  
*Proceedings of the 6th Information Security Conference (ISC'03)*, LNCS 2851, Springer Verlag, October 2003.  
Available files: [pdf](../PAPERS/keyrecovery.pdf)


- B. Pinkas  
**Fair Secure Two-Party Computation**  
*Advances in Cryptology – Eurocrypt '2003 Proceedings*, LNCS 2656, Springer-Verlag, pp. 87-105, May 2003.


- B. Pinkas  
**Cryptographic Techniques for Privacy-Preserving Data Mining**  
*SIGKDD Explorations*, newsletter of the ACM Special Interest Group on Knowledge Discovery and Data Mining, January 2003.  
Available files: [Postscript](../PAPERS/sigkdd.ps) | [pdf](../PAPERS/sigkdd.pdf)


- B. Pinkas and T. Sander  
**Securing Passwords Against Dictionary Attacks**  
*Proceedings of the ACM Computer and Communications Security Conference*, November 2002.  
Available files: [Postscript](../PAPERS/pwdweb.ps) | [pdf](../PAPERS/pwdweb.pdf) | [Slides](../PAPERS/pwdtalk.ppt)


- M. Abadi, N. Glew, B. Horne and B. Pinkas  
**Certified Email with a Light On-line Trusted Third Party: Design and Implementation**  
*Proceedings of WWW2002 (The Eleventh International World Wide Web Conference)*, May 2002.  
Available files: [pdf](../PAPERS/cm.pdf)


- S. Haber and B. Pinkas  
**Combining Public Key Cryptosystems**  
*Proceedings of the ACM Computer and Security Conference*, November 2001.  
Available files: [Postscript](../PAPERS/combined.ps)


- B. Horne, B. Pinkas and T. Sander  
**Escrow Services and Incentives in Peer-to-Peer Networks**  
*Proceedings of the 3rd ACM Conference on Electronic Commerce*, pp. 85-94, 2001.


- B. Pinkas  
**Efficient State Updates for Key Management**  
*Proceedings of the ACM Workshop on Security and Privacy in Digital Rights Management*, November 2001.  
The full version appeared in the *Proceedings of the IEEE*, Special Issue on Enabling Technologies for Digital Rights Management, Vol. 92, No. 6, pp. 910-917, June 2004.  
Available files (full version): [Postscript](../PAPERS/stateupdates.ps) | [pdf](../PAPERS/stateupdates.pdf)


- M. Naor and B. Pinkas  
**Efficient Oblivious Transfer Protocols**  
*Proceedings of SODA 2001 (SIAM Symposium on Discrete Algorithms)*, January 7-9, 2001.  
Available files: [Postscript](../PAPERS/effot.ps)


- M. Naor and B. Pinkas  
**Distributed Oblivious Transfer**  
*Advances in Cryptology – Asiacrypt '00 Proceedings*, LNCS 1976, Springer-Verlag, pp. 200-219, December 2000.  
Available files: [Postscript](../PAPERS/distot.ps)


- Y. Lindell and B. Pinkas  
**Privacy Preserving Data Mining**  
*Advances in Cryptology – Crypto '00 Proceedings*, LNCS 1880, Springer-Verlag, pp. 20-24, August 2000.  
Full version appeared in the *Journal of Cryptology*, Volume 15, Number 3, 2002.  
Available files: [Postscript (conference)](../PAPERS/id3ll.ps) | [Postscript (full version)](../PAPERS/id3-final.ps) | [pdf (full version)](../PAPERS/id3-final.pdf)


- M. Naor and B. Pinkas  
**Efficient Trace and Revoke Schemes**  
*Proceedings of Financial Crypto '2000*, Anguilla, February 2000.  
Available files: [Postscript (full version)](../PAPERS/revocation.ps)


- M. Naor, B. Pinkas and R. Sumner  
**Privacy Preserving Auctions and Mechanism Design**  
*Proceedings of the 1st ACM Conference on Electronic Commerce*, November 1999.  
Available files: [pdf](https://www.wisdom.weizmann.ac.il/~naor/PAPERS/nps.pdf)


- M. Naor and B. Pinkas  
**Oblivious Transfer with Adaptive Queries**  
*Advances in Cryptology – Crypto '99 Proceedings*, LNCS 1666, Springer-Verlag, pp. 573-590, August 1999.  
Available files: [Postscript](../PAPERS/otk.ps)


- V. Anupam, A. Mayer, K. Nissim, B. Pinkas and M. Reiter  
**On the Security of Pay-per-Click and Other Web Advertising Schemes**  
*Proceedings of the 8th World Wide Web Conference*, May 1999.  
(*Computer Networks*, Vol. 31, Issues 11–16, 1999, pp. 1091-1100).  
Available files: [Postscript](../PAPERS/v17.ps) | [HTML](../PAPERS/v17.htm)


- M. Naor, B. Pinkas and O. Reingold  
**Distributed Pseudo-Random Functions and KDCs**  
*Advances in Cryptology – Eurocrypt '99 Proceedings*, LNCS 1592, Springer-Verlag, pp. 327-346, April 1999.  
Available files: [Postscript](../PAPERS/kdc.ps)


- M. Naor and B. Pinkas  
**Oblivious Transfer and Polynomial Evaluation**  
*Proceedings of the 31st Symposium on Theory of Computer Science (STOC)*, Atlanta, GA, pp. 245-254, May 1-4, 1999.


- R. Canetti, J. Garay, G. Itkis, D. Micciancio, M. Naor and B. Pinkas  
**Multicast Security: A Taxonomy and Some Efficient Constructions**  
*Proceedings of INFOCOM '99*, Vol. 2, pp. 708-716, New York, NY, March 1999.  
Available files: [Postscript](../PAPERS/infocom.ps)


- M. Naor and B. Pinkas  
**Threshold Traitor Tracing**  
*Advances in Cryptology – Crypto '98 Proceedings*, LNCS 1462, Springer-Verlag, pp. 502-517, 1998.  
Available files: [Postscript](../PAPERS/ttt.ps)


- B. Chor, A. Fiat, M. Naor and B. Pinkas  
**Tracing Traitors**  
*IEEE Transactions on Information Theory*, Vol. 46, No. 3, pp. 893-910, May 2000.  
Available files: [Postscript](../PAPERS/ttit.ps)

- M. Naor and B. Pinkas  
  **Secure and Efficient Metering**  
  *Eurocrypt '98*  
  [Postscript](../PAPERS/metereuro.ps)

- M. Naor and B. Pinkas  
  **Secure Accounting and Auditing on the Web**  
  *7th World Wide Web Conference* (Computer Networks, Vol. 30, Issues 1-7, 1998, pp. 541-550)  
  [HTML](../PAPERS/www7paper/p336.htm)

- M. Naor and B. Pinkas  
  **Visual Authentication and Identification**  
  *Crypto '97*  
  [Postscript (proceedings)](../PAPERS/vconf.ps) [Postscript (full version)](../PAPERS/vj.ps)

- J. McInnes and B. Pinkas  
  **On the Impossibility of Private Key Cryptography with Weakly Random Keys**  
  *Crypto '90*  

### Internet Drafts and Technical Reports

- R. Canetti and B. Pinkas  
  **A Taxonomy of Multicast Security Issues**  
  An updated version of internet draft draft-irtf-smug-taxonomy-00.txt, April 1999 (the original version was published in June 1998).  
  Available files: [Text](../PAPERS/draft-irtf-smug-taxonomy-00.txt)

- R. Canetti, A. Herzberg, and B. Pinkas  
  **Distributed Computing Simulator**  
  TR #566, Dept. of Computer Science, Technion, June 1989.
