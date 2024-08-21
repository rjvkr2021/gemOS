#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */
#define _2MB 2097152
#define PGD_SHIFT 39
#define PGD_MASK 0xFF8000000000 // 9 ones followed by 39 zeros
#define PUD_SHIFT 30
#define PUD_MASK 0x7FC0000000 // 9 ones followed by 30 zeros
#define PMD_SHIFT 21
#define PMD_MASK 0x3FE00000 // 9 ones followed by 21 zeros
#define PTE_SHIFT 12
#define PTE_MASK 0x1FF000 // 9 ones followed by 12 zeros
#define PRESENT_MASK 1
#define READ_WRITE_MASK 8
#define USER_SUPERVISOR_MASK 16
#define W_MASK 2

/**
 * mmap system call implementation.
 */

struct vm_area* create_node(u64 start, u64 end, int prot){
    struct vm_area *temp = (struct vm_area*)os_alloc(sizeof(struct vm_area));
    temp->vm_start = start;
    temp->vm_end = end;
    temp->access_flags = prot;
    temp->vm_next = NULL;
    stats->num_vm_area++;
    return temp;
}

u64 max(u64 a, u64 b){
    if(a > b){
        return a;
    }
    return b;
}

u64 min(u64 a, u64 b){
    if(a < b){
        return a;
    }
    return b;
}

void find_intervals_intersection(u64 a, u64 b, u64 c, u64 d, u64 *e, u64 *f){
    if(b <= c || d <= a){
        *e = *f;
    }
    else{
        u64 x = max(a, c);
        u64 y = min(b, d);
        if(x < y){
            *e = x;
            *f = y;
        }
        else{
            *e = *f;
        }
    }
}

int addr_available(struct vm_area *vm_area, u64 addr, int length){
    u64 a = addr, b = addr + length;
    struct vm_area *temp = vm_area;
    while(temp){
        u64 c = temp->vm_start, d = temp->vm_end, e, f;
        find_intervals_intersection(a, b, c, d, &e, &f);
        if(e != f){
            return 0;
        }
        temp = temp->vm_next;
    }
    return 1;
}

struct vm_area* find_next_node(struct vm_area *vm_area, u64 addr){
    struct vm_area *temp = vm_area;
    while(temp){
        if(temp->vm_start > addr){
            break;
        }
        temp = temp->vm_next;
    }
    return temp;
}

u64 find_lowest_addr(struct vm_area *vm_area, int length){
    u64 prev_end = MMAP_AREA_START + PAGE_SIZE;
    struct vm_area *curr = vm_area;
    while(curr){
        if(curr->vm_start - prev_end >= length){
            break;
        }
        prev_end = curr->vm_end;
        curr = curr->vm_next;
    }    
    return prev_end;
}

void add_to_start(struct vm_area *new_node){
    struct exec_context *current = get_current_ctx();
    struct vm_area *vm_area = current->vm_area;
    new_node->vm_next = vm_area->vm_next;
    vm_area->vm_next = new_node;
}

void insert(struct vm_area *vm_area, u64 addr, int length, int prot){
    struct vm_area *new_node = create_node(addr, addr + length, prot);
    if(!vm_area || new_node->vm_start < vm_area->vm_start){
        add_to_start(new_node);
        return;
    }
    struct vm_area *prev = vm_area, *curr = vm_area->vm_next;
    while(curr){
        if(curr->vm_start > new_node->vm_start){
            break;
        }
        prev = curr;
        curr = curr->vm_next;
    }
    prev->vm_next = new_node;
    new_node->vm_next = curr;
}

void merge(struct vm_area *vm_area){
    if(!vm_area){
        return;
    }
    struct vm_area *prev = vm_area, *curr = vm_area->vm_next;
    while(curr){
        if(prev->vm_end == curr->vm_start && prev->access_flags == curr->access_flags){
            prev->vm_end = curr->vm_end;
            prev->vm_next = curr->vm_next;
            os_free(curr, sizeof(struct vm_area));
            stats->num_vm_area--;
            curr = prev;
        }
        else{
            prev = curr;
        }
        curr = curr->vm_next;
    }
}

long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    if(!current || length <= 0 || length > _2MB || !(prot == PROT_READ || prot == (PROT_READ | PROT_WRITE)) || !(flags == 0 || flags == MAP_FIXED)){
        return -1;
    }
    if(length%(PAGE_SIZE)){
        length = (length/(PAGE_SIZE) + 1)*PAGE_SIZE;
    }
    if(!(current->vm_area)){
        current->vm_area = create_node(MMAP_AREA_START, MMAP_AREA_START + PAGE_SIZE, 0);
    }
    struct vm_area *vm_area = current->vm_area;
    if(addr){
        if(!(MMAP_AREA_START + PAGE_SIZE <= addr && addr + length < MMAP_AREA_END)){
            return -1;
        }
        if(!addr_available(vm_area->vm_next, addr, length)){
            if(flags == MAP_FIXED){
                return -1;
            }
            else{
                addr = find_lowest_addr(vm_area->vm_next, length);
            }
        }
    }
    else{
        if(flags == MAP_FIXED){
            return -1;
        }
        addr = find_lowest_addr(vm_area->vm_next, length);
    }
    if(!(MMAP_AREA_START + PAGE_SIZE <= addr && addr + length < MMAP_AREA_END)){
        return -1;
    }
    insert(vm_area->vm_next, addr, length, prot);
    merge(vm_area->vm_next);
    return addr;
}

int page_exists(struct exec_context *current, u64 addr, u64 *_pgd_addr, u64 *_pud_addr, u64 *_pmd_addr, u64 *_pte_addr){
    u64 pgd = current->pgd;
    u64 pgd_base = osmap(pgd);
    u64 pgd_offset = (addr & PGD_MASK) >> PGD_SHIFT;
    u64 *pgd_addr = pgd_base + pgd_offset*8;
    u64 pgd_t = *pgd_addr;
    if((pgd_t & PRESENT_MASK) == 0){
        return 0;
    }
    u64 pud_base = pgd_t & 0xFFFFFFFFFFFFF000;
    u64 pud_offset = (addr & PUD_MASK) >> PUD_SHIFT;
    u64 *pud_addr = pud_base + pud_offset*8;
    u64 pud_t = *pud_addr;
    if((pud_t & PRESENT_MASK) == 0){
        return 0;
    }
    u64 pmd_base = pud_t & 0xFFFFFFFFFFFFF000;
    u64 pmd_offset = (addr & PMD_MASK) >> PMD_SHIFT;
    u64 *pmd_addr = pmd_base + pmd_offset*8;
    u64 pmd_t = *pmd_addr;
    if((pmd_t & PRESENT_MASK) == 0){
        return 0;
    } 
    u64 pte_base = pmd_t & 0xFFFFFFFFFFFFF000;
    u64 pte_offset = (addr & PTE_MASK) >> PTE_SHIFT;
    u64 *pte_addr = pte_base + pte_offset*8;
    u64 pte_t = *pte_addr;
    if((pte_t & PRESENT_MASK) == 0){
        return 0;
    }
    *_pgd_addr = pgd_addr;
    *_pud_addr = pud_addr;
    *_pmd_addr = pmd_addr;
    *_pte_addr = pte_addr;
    return 1;
}

void mprotect_page(struct exec_context *current, u64 addr, int prot){
    u64 _pgd_addr, _pud_addr, _pmd_addr, _pte_addr;
    if(!page_exists(current, addr, &_pgd_addr, &_pud_addr, &_pmd_addr, &_pte_addr)){
        return;
    }
    u64 *pte_addr = _pte_addr;
    u64 pte_t = *pte_addr;
    if(get_pfn_refcount(pte_t >> 12) > 1){
        return;
    }
    if(prot & W_MASK){
        pte_t |= READ_WRITE_MASK;
    }
    else{
        pte_t &= 0xFFFFFFFFFFFFFFF7;
    }
    *pte_addr = pte_t;
    asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

/**
 * mprotect System call Implementation.
 */

long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if(!current || !(MMAP_AREA_START + PAGE_SIZE <= addr && addr + length < MMAP_AREA_END) || length <= 0 || !(prot == PROT_READ || prot == (PROT_READ | PROT_WRITE))){
        return -1;
    }
    if(length%(PAGE_SIZE)){
        length = (length/(PAGE_SIZE) + 1)*PAGE_SIZE;
    }
    u64 a = addr, b = addr + length;
    struct vm_area *vm_area = current->vm_area;
    struct vm_area *prev = vm_area, *curr = vm_area->vm_next;
    while(curr){
        u64 c = curr->vm_start, d = curr->vm_end, e, f;
        find_intervals_intersection(a, b, c, d, &e, &f);
        if(e != f){
            if(curr->vm_start == e && curr->vm_end == f){
                curr->access_flags = prot;
                prev = curr;
            }
            else if(curr->vm_start == e){
                struct vm_area *temp = create_node(e, f, prot);
                curr->vm_start = f;
                temp->vm_next = curr;
                prev->vm_next = temp;
                prev = curr;
            }
            else if(curr->vm_end == f){
                struct vm_area *temp = create_node(e, f, prot);
                curr->vm_end = e;
                temp->vm_next = curr->vm_next;
                curr->vm_next = temp;
                prev = curr = temp;
            }
            else{
                struct vm_area *temp1 = create_node(e, f, prot);
                struct vm_area *temp2 = create_node(f, curr->vm_end, curr->access_flags);
                curr->vm_end = e;
                temp1->vm_next = temp2;
                temp2->vm_next = curr->vm_next;
                curr->vm_next = temp1;
                prev = curr = temp2;
            }
            for(u64 i = e; i < f; i += PAGE_SIZE){
                mprotect_page(current, i, prot);
            }
        }
        else{
            prev = curr;
        }
        curr = curr->vm_next;
    }
    merge(vm_area);
    return 0;
}

void unmap_page(struct exec_context *current, u64 addr){
    u64 _pgd_addr, _pud_addr, _pmd_addr, _pte_addr;
    if(!page_exists(current, addr, &_pgd_addr, &_pud_addr, &_pmd_addr, &_pte_addr)){
        return;
    }
    u64 *pgd_addr = _pgd_addr, *pud_addr = _pud_addr, *pmd_addr = _pmd_addr, *pte_addr = _pte_addr;
    u64 pgd_t = *pgd_addr, pud_t = *pud_addr, pmd_t = *pmd_addr, pte_t = *pte_addr;
    put_pfn(pte_t >> 12);
    if(get_pfn_refcount(pte_t >> 12) == 0){
        os_pfn_free(USER_REG, pte_t >> 12);
    }
    *pte_addr = 0;
    asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

/**
 * munmap system call implemenations
 */

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if(!current || !(MMAP_AREA_START + PAGE_SIZE <= addr && addr + length < MMAP_AREA_END) || length <= 0){
        return -1;
    }
    if(length%(PAGE_SIZE)){
        length = (length/(PAGE_SIZE) + 1)*PAGE_SIZE;
    }
    u64 a = addr, b = addr + length;
    struct vm_area *vm_area = current->vm_area;
    struct vm_area *prev = vm_area, *curr = vm_area->vm_next;
    while(curr){
        u64 c = curr->vm_start, d = curr->vm_end, e, f;
        find_intervals_intersection(a, b, c, d, &e, &f);
        if(e != f){
            if(curr->vm_start == e && curr->vm_end == f){
                prev->vm_next = curr->vm_next;
                os_free(curr, sizeof(struct vm_area));
                stats->num_vm_area--;
                curr = prev;
            }
            else if(curr->vm_start == e){
                curr->vm_start = f;
                prev = curr;
            }
            else if(curr->vm_end == f){
                curr->vm_end = e;
                prev = curr;
            }
            else{
                struct vm_area *temp = create_node(f, curr->vm_end, curr->access_flags);
                temp->vm_next = curr->vm_next;
                curr->vm_end = e;
                curr->vm_next = temp;
                prev = curr = temp;
            }
            for(u64 i = e; i < f; i += PAGE_SIZE){
                unmap_page(current, i);
            }
        }
        else{
            prev = curr;
        }
        curr = curr->vm_next;
    }
    return 0;
}

u64 change_bits(u64 a, u64 b){
    a &= 0xFFF;
    b = b << 12;
    a |= b;
    return a;
}

void map_page(struct exec_context *current, u64 addr, int access_flags){
    u64 pgd = current->pgd;
    u64 pgd_base = osmap(pgd);
    u64 pgd_offset = (addr & PGD_MASK) >> PGD_SHIFT;
    u64 *pgd_addr = pgd_base + pgd_offset*8;
    u64 pgd_t = *pgd_addr;
    if((pgd_t & PRESENT_MASK) == 0){
        u64 pfn = os_pfn_alloc(OS_PT_REG);
        pgd_t = change_bits(pgd_t, pfn);
        pgd_t |= PRESENT_MASK | READ_WRITE_MASK | USER_SUPERVISOR_MASK;
    }
    *pgd_addr = pgd_t;
    u64 pud_base = pgd_t & 0xFFFFFFFFFFFFF000;
    u64 pud_offset = (addr & PUD_MASK) >> PUD_SHIFT;
    u64 *pud_addr = pud_base + pud_offset*8;
    u64 pud_t = *pud_addr;
    if((pud_t & PRESENT_MASK) == 0){
        u64 pfn = os_pfn_alloc(OS_PT_REG);
        pud_t = change_bits(pud_t, pfn);
        pud_t |= PRESENT_MASK | READ_WRITE_MASK | USER_SUPERVISOR_MASK;
    }
    *pud_addr = pud_t;
    u64 pmd_base = pud_t & 0xFFFFFFFFFFFFF000;
    u64 pmd_offset = (addr & PMD_MASK) >> PMD_SHIFT;
    u64 *pmd_addr = pmd_base + pmd_offset*8;
    u64 pmd_t = *pmd_addr;
    if((pmd_t & PRESENT_MASK) == 0){
        u64 pfn = os_pfn_alloc(OS_PT_REG);
        pmd_t = change_bits(pmd_t, pfn);
        pmd_t |= PRESENT_MASK | READ_WRITE_MASK | USER_SUPERVISOR_MASK;
    } 
    *pmd_addr = pmd_t;
    u64 pte_base = pmd_t & 0xFFFFFFFFFFFFF000;
    u64 pte_offset = (addr & PTE_MASK) >> PTE_SHIFT;
    u64 *pte_addr = pte_base + pte_offset*8;
    u64 pte_t = *pte_addr;
    if((pte_t & PRESENT_MASK) == 0){
        u64 pfn = os_pfn_alloc(USER_REG);
        pte_t = change_bits(pte_t, pfn);
        pte_t |= PRESENT_MASK | USER_SUPERVISOR_MASK;
        if(access_flags & W_MASK){
            pte_t |= READ_WRITE_MASK;
        }
        else{
            pte_t &= 0xFFFFFFFFFFFFFFF7;
        }
    }
    *pte_addr = pte_t;
}

/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * create_noded using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    if(!current || !(MMAP_AREA_START + PAGE_SIZE <= addr && addr < MMAP_AREA_END) || !(error_code == 0x4 || error_code == 0x6 || error_code == 0x7)){
        return -1;
    }
    struct vm_area *vm_area = current->vm_area;
    struct vm_area *temp = vm_area->vm_next;
    while(temp){
        if(temp->vm_start <= addr && addr < temp->vm_end){
            break;
        }
        temp = temp->vm_next;
    }
    if(!temp){
        return -1;
    }
    int error_w = error_code & W_MASK;
    u32 access_flags = temp->access_flags;
    int access_flags_w = access_flags & W_MASK;

    if(error_w && (access_flags_w == 0)){
        return -1;
    }
    if(error_code == 0x7){ // CoW fault
        return handle_cow_fault(current, addr, temp->access_flags);
    }
    map_page(current, addr, access_flags);
    return 1;
}

/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the 
 * end of this function (e.g., setup_child_context etc.)
 */

void copy_vm_area(struct exec_context *parent_ctx, struct exec_context *child_ctx){
    child_ctx->vm_area = create_node(MMAP_AREA_START, MMAP_AREA_START + PAGE_SIZE, 0);
    struct vm_area *parent_temp = parent_ctx->vm_area->vm_next, *child_temp = child_ctx->vm_area;
    while(parent_temp){
        child_temp->vm_next = create_node(parent_temp->vm_start, parent_temp->vm_end, parent_temp->access_flags);
        parent_temp = parent_temp->vm_next;
        child_temp = child_temp->vm_next;
    }
}

void copy_exec_context(struct exec_context *parent_ctx, struct exec_context *child_ctx){
    child_ctx->type = parent_ctx->type;
    child_ctx->used_mem = parent_ctx->used_mem;
    for(int i = 0; i < MAX_MM_SEGS; i++){
        child_ctx->mms[i] = parent_ctx->mms[i];
    }
    copy_vm_area(parent_ctx, child_ctx);
    for(int i = 0; i < CNAME_MAX; i++){
        child_ctx->name[i] = parent_ctx->name[i];
    }
    child_ctx->regs = parent_ctx->regs;
    child_ctx->pending_signal_bitmap = parent_ctx->pending_signal_bitmap;
    for(int i = 0; i < MAX_SIGNALS; i++){
        child_ctx->sighandlers[i] = parent_ctx->sighandlers[i];
    }
    child_ctx->ticks_to_sleep = parent_ctx->ticks_to_sleep;
    child_ctx->alarm_config_time = parent_ctx->alarm_config_time;
    child_ctx->ticks_to_alarm = parent_ctx->ticks_to_alarm;
    for(int i = 0; i < MAX_OPEN_FILES; i++){
        child_ctx->files[i] = parent_ctx->files[i];
    }
    child_ctx->ctx_threads = parent_ctx->ctx_threads;
}

void copy_page(struct exec_context *parent_ctx, struct exec_context *child_ctx, u64 addr){
    u64 _pgd_addr, _pud_addr, _pmd_addr, _pte_addr;
    if(page_exists(parent_ctx, addr, &_pgd_addr, &_pud_addr, &_pmd_addr, &_pte_addr)){
        map_page(child_ctx, addr, PROT_READ);
        u64 *parent_pte_addr = _pte_addr;
        u64 parent_pte_t = *parent_pte_addr;
        page_exists(child_ctx, addr, &_pgd_addr, &_pud_addr, &_pmd_addr, &_pte_addr);
        u64 *child_pte_addr = _pte_addr;
        u64 child_pte_t = *child_pte_addr;
        put_pfn(child_pte_t >> 12);
        os_pfn_free(USER_REG, child_pte_t >> 12);
        get_pfn(parent_pte_t >> 12);
        *parent_pte_addr = (parent_pte_t & 0xFFFFFFFFFFFFFFF7);
        *child_pte_addr = *parent_pte_addr;
    }
}

void copy_page_table(struct exec_context *parent_ctx, struct exec_context *child_ctx){
    child_ctx->pgd = os_pfn_alloc(OS_PT_REG);
    for(u64 i = parent_ctx->mms[MM_SEG_CODE].start; i < parent_ctx->mms[MM_SEG_CODE].next_free; i += PAGE_SIZE){
        copy_page(parent_ctx, child_ctx, i);
    }
    for(u64 i = parent_ctx->mms[MM_SEG_RODATA].start; i < parent_ctx->mms[MM_SEG_RODATA].next_free; i += PAGE_SIZE){
        copy_page(parent_ctx, child_ctx, i);
    }
    for(u64 i = parent_ctx->mms[MM_SEG_DATA].start; i < parent_ctx->mms[MM_SEG_DATA].next_free; i += PAGE_SIZE){
        copy_page(parent_ctx, child_ctx, i);
    }
    for(u64 i = parent_ctx->mms[MM_SEG_STACK].start; i < parent_ctx->mms[MM_SEG_STACK].end; i += PAGE_SIZE){
        copy_page(parent_ctx, child_ctx, i);
    }
    struct vm_area *temp = parent_ctx->vm_area->vm_next;
	while(temp){
        for(u64 i = temp->vm_start; i < temp->vm_end; i += PAGE_SIZE){
            copy_page(parent_ctx, child_ctx, i);
        }
		temp = temp->vm_next;
	}
}

long do_cfork(){
    u32 pid;
    struct exec_context *parent_ctx = get_current_ctx();
    struct exec_context *child_ctx = get_new_ctx();
    /* Do not modify above lines
    * 
    * */   
    /*--------------------- Your code [start]---------------*/
    copy_exec_context(parent_ctx, child_ctx);
    pid = child_ctx->pid;
    child_ctx->ppid = parent_ctx->pid;
    copy_page_table(parent_ctx, child_ctx);
    /*--------------------- Your code [end] ----------------*/

    /*
    * The remaining part must not be changed
    */
    copy_os_pts(parent_ctx->pgd, child_ctx->pgd);
    do_file_fork(child_ctx);
    setup_child_context(child_ctx);
    return pid;
}



/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data) 
 * it is called when there is a CoW violation in these areas. 
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 addr, int access_flags)
{
    if(!current){
        return -1;
    }
    u64 _pgd_addr, _pud_addr, _pmd_addr, _pte_addr;
    page_exists(current, addr, &_pgd_addr, &_pud_addr, &_pmd_addr, &_pte_addr);
    u64 *pgd_addr = _pgd_addr, *pud_addr = _pud_addr, *pmd_addr = _pmd_addr, *pte_addr = _pte_addr;
    u64 pgd_t = *pgd_addr, pud_t = *pud_addr, pmd_t = *pmd_addr, pte_t = *pte_addr;
    if(get_pfn_refcount(pte_t >> 12) > 1){
        put_pfn(pte_t >> 12);
        u64 pfn_new = os_pfn_alloc(USER_REG);
        memcpy(osmap(pfn_new), pte_t & 0xFFFFFFFFFFFFF000, PAGE_SIZE);
        pte_t = change_bits(pte_t, pfn_new);
        pte_t |= PRESENT_MASK | USER_SUPERVISOR_MASK;
    }
    pte_t |= READ_WRITE_MASK;
    *pte_addr = pte_t;
    asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
    return 1;
}
