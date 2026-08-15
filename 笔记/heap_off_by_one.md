# off-by-one利用思路


- 关于这个大概分为两种思路
```py
  一是修改后一个chunk(chunkA)的size,并free chunkA从而使chunkA与chunkB合并，这个较为
常用，因为可以绕开unlink对presize-size以及fd-bk双链表的检查
  二是修改后一个chunk的pre in use位，这个多用于off by null,在2.28之前较为简单，只需要
伪造chunkA的presize位并置空pre in use，然后free chunkA，触发向前合并形成堆块重叠，其中最前面的chunkB需要位于双链表中(unsortedbin)从而绕过fd-bk检查
  关于二方法2.28之后，由于unlink多了presize的检查，因此较为麻烦，因为无法修改正常
unsortedbin中chunk的size,因此我们需要伪造一个chunk同时绕过两个检查，这个过程涉及对largebin中chunk的fd_nextsize和bk_nextsize的利用，在此不赘述，可见例题balsn_ctf_2019-plaintext
```




- 溢出字节为**可控制任意字节**：通过修改大小造成块结构之间出现重叠，从而泄露其他块数据，或是覆盖其他块数据。也可使用 NULL 字节溢出的方法
- 溢出字节为 **NULL 字节**：在 size 为 0x100 的时候，溢出 NULL 字节可以使得 prev_in_use 位被清，这样前块会被认为是 free 块。  
（1） 这时可以选择使用 unlink 方法（见 unlink 部分）进行处理.  （2） 另外，这时 prev_size 域就会启用，就可以伪造 prev_size ，从而造成块之间发生重叠。此方法的关键在于 unlink 的时候没有检查按照 prev_size 找到的块的大小与prev_size 是否一致。
- 最新版本代码中，已加入针对 2 中后一种方法的 check ，但是在 2.28 及之前版本并没有该 check 。
```c
/* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      /* 后两行代码在最新版本中加入，则 2 的第二种方法无法使用，但是 2.28 及之前都没有问题 */
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
```
#### 关于pre_size复用对溢出一字节覆盖位置的影响
- 当两个相邻的chunk在一起时，如果前一个chunk处于使用状态，那么后一个chunk的prev_size成员就不使用了，这些看上去似乎是一种浪费。因此，系统做了如下的规定：
- 当前一个chunk申请的数据空间申请的大小对16**取余后**，如果多出来的大小小于等于8字节，那么这个多出来的大小就放入下一个chunk的**prev_size**中存储。`（**这种情况下溢出的一字节覆盖的便是size的低位**）`

#### 补充：关于free_hook
- 在老版本中存在一个函数指针名为**__free_hook**,其中存放着自定义的free函数地址，free函数真正执行时会检查该指针是否存在，若存在则执行其指向的函数，通过**修改其中存放的函数地址**便可以实现执行流劫持

### 例题
[解题链接](https://www.uf4te.cn/posts/18c02ebd.html#post-comment)
- （/mnt/d/download/pwn/pwn_notes/题目/堆/off_by_one/samples/b00ks）
由本题产生的收获：

- 当malloc一个非常大的chunk时会**使用mmap进行扩展**，从而产生mmap区，该区与libc基地址**偏移一般固定**，所以可通过泄露mmap区地址计算libc_base

- 本题另外一种泄露libc的方法是利用unsorted bin,当一个较大的chunk被free时会**进入unsorted bin**(最新版本的libc想要利用这种方式需要先**把tcache填满**)，  
unsorted bin为双向链表，第一个chunk的bk指**向main_arena.top**,main_arena.top在main_arena结构体中偏移固定，main_arena在libc中偏移固定

```py

因为 unsorted bin 是双向链表，所以第一个 unsorted bin 的 bk 也就指向了 bin[1]
如果我们能够打印出第一个 unsorted bin 的 bk，也就相当于得到了 bins[1] 地址，而 bins[1] 在 libc 中，也就可以根据偏移计算 libc 基地址

当 free 的 chunk 大小 >= 144 字节时，chunk 会放到 unsorted bin 中
```

### 例题
- （/mnt/d/download/ctf/pwn/pwn_notes/题目/堆/off_by_one/plaidctf）
- 利用方法：
``` py
通过off by one修改pre size和size来实现chunk overlap，进而得到chunk的合并实现UAF等写入操作
并利用unsorted bin的fd bk指针泄露libc地址进而得到one gadget和malloc_hook地址
通过写入修改fastbin的fd指针来实现fastbin attack从而实现任意写，将malloc_hook修改为onegadget
最后执行malloc操作即可执行onegadget
```
- 难点在于对chunk的布局以及整体思路
-细节点：
```py
这一题的环境比较老，因此这些方法在新版本libc中不适用，比如chunk合并时的检查以及tcache机制等
fastbin attack时fd指向的是下一个fastbin的header,需要通过一些偏移的调整来使fake fastbin的size合法
在free chunk时当chunk的size大小超过一个阈值时会跳过fastbin直接进入unsorted bin(没有tcache)


```