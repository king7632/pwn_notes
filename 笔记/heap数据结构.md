记录学习时的总结与感悟

# malloc申请chunk时流程
malloc(size)
  ↓
1. 规格化大小（对齐 + 加头部）
  ↓
2. tcache
     有对应大小 → 直接返回
  ↓
3. fastbin
     在 fastbin 范围且非空 → 取头结点返回
  ↓
4. smallbin
     对应 bin 非空 → unlink 返回
  ↓
5. unsorted bin
     遍历：
        - 有刚好合适的 → 返回
        - 不合适的 → 按大小放入 smallbin / largebin
  ↓
6. largebin
     找 ≥ 目标大小的最小 chunk
        - 能切割就 split
        - 返回
  ↓
7. 如果需要 → malloc_consolidate
     把 fastbin 全部合并进 unsorted
  ↓
8. top chunk
     足够大 → 切割返回
  ↓
9. sysmalloc
     扩展堆（brk/mmap）

# free chunk流程
malloc:
- tcache → fastbin → smallbin → unsorted → top chunk
- 其中tcache中chunk的存放是**单链表**，遵循**LIFO**原则