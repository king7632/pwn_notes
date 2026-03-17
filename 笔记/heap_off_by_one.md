# off-by-one利用思路
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
unsorted bin为双向链表，第一个chunk的bk指**向main_arena.top**,main_arena.top在main_arena结构体中偏移固定，而main_arena在libc中的偏移可以通过**libc.symbols['main_arena']**求得

```py
因为 unsorted bin 是双向链表，所以第一个 unsorted bin 的 bk 也就指向了 bin[1]
如果我们能够打印出第一个 unsorted bin 的 bk，也就相当于得到了 bins[1] 地址，而 bins[1] 在 libc 中，也就可以根据偏移计算 libc 基地址
```