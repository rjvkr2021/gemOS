#include<context.h>
#include<memory.h>
#include<lib.h>
#include<entry.h>
#include<file.h>
#include<tracer.h>


///////////////////////////////////////////////////////////////////////////
//// 		Start of Trace buffer functionality 		      /////
///////////////////////////////////////////////////////////////////////////

int is_valid_mem_range(unsigned long buff, u32 count, int access_bit) 
{
	int mask;
	if(access_bit == 0){
		mask = 1;
	}
	else if(access_bit == 1){
		mask = 2;
	}
	else{
		mask = 4;
	}
	struct exec_context *ctx = get_current_ctx();
	if(ctx == NULL){
		return -1;
	}
	struct mm_segment *mms = ctx->mms;
	if(mms == NULL){
		return -1;
	}
	struct vm_area *vm_area = ctx->vm_area;
	unsigned long start = buff, end = buff + count - 1;
	for(int i = 0; i < MAX_MM_SEGS; i++){
		if(i == MM_SEG_STACK && (mms[i].start <= start && end <= mms[i].end - 1) && (mms[i].access_flags & mask)){
			return 0;
		}
		else if((mms[i].start <= start && end <= mms[i].next_free - 1) && (mms[i].access_flags & mask)){
			return 0;
		}
	}
	while(vm_area != NULL){
		if((vm_area->vm_start <= start && end <= vm_area->vm_end - 1) && (vm_area->access_flags & mask)){
			return 0;
		}
		vm_area = vm_area->vm_next;
	}
	return -1;
}

long trace_buffer_close(struct file *filep)
{
	if(filep == NULL){
		return -EINVAL;
	}
	struct trace_buffer_info *trace_buffer = filep->trace_buffer;
	if(trace_buffer == NULL){
		return -EINVAL;
	}
	struct fileops *fops = filep->fops;
	if(fops == NULL){
		return -EINVAL;
	}
	char *arr = trace_buffer->arr;
	if(arr == NULL){
		return -EINVAL;
	}
	os_page_free(USER_REG, filep->trace_buffer->arr);
	filep->trace_buffer->arr = NULL;
	os_free(filep->fops, sizeof(struct fileops));
	filep->fops = NULL;
	os_free(filep->trace_buffer, sizeof(struct trace_buffer_info));
	filep->trace_buffer = NULL;
	os_free(filep, sizeof(struct file));
	filep = NULL;
	return 0;	
}

int trace_buffer_read_helper(struct file *filep, char *buff, u32 count){
	if(filep == NULL || buff == NULL || count < 0){
		return -EINVAL;
	}
	if(count == 0){
		return 0;
	}
	int type = filep->type;
	int mode = filep->mode;
	if(type != TRACE_BUFFER){
		return -EINVAL;
	}
	struct trace_buffer_info *trace_buffer = filep->trace_buffer;
	if(trace_buffer == NULL){
		return -EINVAL;
	}
	int read_offset = trace_buffer->read_offset;
	int write_offset = trace_buffer->write_offset;
	int used_space = trace_buffer->used_space;
	char *arr = trace_buffer->arr;
	if(arr == NULL){
		return -EINVAL;
	}
	if(used_space == 0){
		return 0;
	}
	int i = 0;
	buff[i] = arr[read_offset];
	i++;
	used_space--;
	read_offset = (read_offset + 1)%TRACE_BUFFER_MAX_SIZE;
	while(read_offset != write_offset && i < count){
		buff[i] = arr[read_offset];
		i++;
		used_space--;
		read_offset = (read_offset + 1)%TRACE_BUFFER_MAX_SIZE;
	}
	trace_buffer->read_offset = read_offset;
	trace_buffer->used_space = used_space;
	filep->offp = read_offset;
	return i;
}

int trace_buffer_read(struct file *filep, char *buff, u32 count)
{
	if(filep == NULL || buff == NULL || count < 0){
		return -EINVAL;
	}
	if(is_valid_mem_range((unsigned long)buff, count, 1) < 0){
		return -EBADMEM;
	}	
	return trace_buffer_read_helper(filep, buff, count);
}

int trace_buffer_write_helper(struct file *filep, char *buff, u32 count)
{
	if(filep == NULL || buff == NULL || count < 0){
		return -EINVAL;
	}
	if(count == 0){
		return 0;
	}
	int type = filep->type;
	int mode = filep->mode;
	if(type != TRACE_BUFFER){
		return -EINVAL;
	}
	struct trace_buffer_info *trace_buffer = filep->trace_buffer;
	if(trace_buffer == NULL){
		return -EINVAL;
	}
	int read_offset = trace_buffer->read_offset;
	int write_offset = trace_buffer->write_offset;
	int used_space = trace_buffer->used_space;
	char *arr = trace_buffer->arr;
	if(arr == NULL){
		return -EINVAL;
	}
	if(used_space == TRACE_BUFFER_MAX_SIZE){
		return 0;
	}
	int i = 0;
	arr[write_offset] = buff[i];
	i++;
	used_space++;
	write_offset = (write_offset + 1)%TRACE_BUFFER_MAX_SIZE;
	while(write_offset != read_offset && i < count){
		arr[write_offset] = buff[i];
		i++;
		used_space++;
		write_offset = (write_offset + 1)%TRACE_BUFFER_MAX_SIZE;
	}
	trace_buffer->write_offset = write_offset;
	trace_buffer->used_space = used_space;
	filep->offp = write_offset;
	return i;
}

int trace_buffer_write(struct file *filep, char *buff, u32 count){
	if(filep == NULL || buff == NULL || count < 0){
		return -EINVAL;
	}
	if(is_valid_mem_range((unsigned long)buff, count, 0) < 0){
		return -EBADMEM;
	}
	return trace_buffer_write_helper(filep, buff, count);
}

int sys_create_trace_buffer(struct exec_context *current, int mode)
{
	if(current == NULL){
		return -EINVAL;
	}
	if(mode != O_READ && mode != O_WRITE && mode != O_RDWR){
		return -EINVAL;
	}
	struct file **files = current->files;
	if(files == NULL){
		return -EINVAL;
	}
	int lowest_free_fd = 0;
	while(lowest_free_fd < MAX_OPEN_FILES && files[lowest_free_fd] != NULL){
		lowest_free_fd++;
	}
	if(lowest_free_fd == MAX_OPEN_FILES){
		return -EINVAL;
	}
	files[lowest_free_fd] = (struct file*)os_alloc(sizeof(struct file));
	if(files[lowest_free_fd] == NULL){
		return -ENOMEM;
	}
	struct file *filep = files[lowest_free_fd];
	filep->type = TRACE_BUFFER;
	filep->mode = mode;
	filep->offp = 0;
	filep->ref_count = 1;
	filep->inode = NULL;
	filep->trace_buffer = (struct trace_buffer_info*)os_alloc(sizeof(struct trace_buffer_info));
	if(filep->trace_buffer == NULL){
		return -ENOMEM;
	}
	filep->fops = (struct fileops*)os_alloc(sizeof(struct fileops));
	if(filep->fops == NULL){
		return -ENOMEM;
	}
	struct trace_buffer_info *trace_buffer = filep->trace_buffer;
	struct fileops *fops = filep->fops;
	trace_buffer->read_offset = 0;
	trace_buffer->write_offset = 0;
	trace_buffer->used_space = 0;
	trace_buffer->arr = (char*)os_page_alloc(USER_REG);
	if(trace_buffer->arr == NULL){
		return -ENOMEM;
	}
	fops->read = trace_buffer_read;
	fops->write = trace_buffer_write;
	fops->lseek = NULL;
	fops->close = trace_buffer_close;
	return lowest_free_fd;
}

///////////////////////////////////////////////////////////////////////////
//// 	        	Start of strace functionality 		      	      /////
///////////////////////////////////////////////////////////////////////////

int get_n_args(u64 syscall_num){
	int n_args[100];
	n_args[1] = 1; // exit
	n_args[2] = 0; // getpid
	n_args[4] = 2; // expand
	// n_args[5] = ; // shrink
	// n_args[6] = ; // alarm
	n_args[7] = 1; // sleep
	n_args[8] = 2; // signal
	n_args[9] = 2; // clone
	n_args[10] = 0; // fork
	n_args[11] = 0; // stats
	n_args[12] = 1; // configure
	n_args[13] = 0; // phys_info
	n_args[14] = 1; // dump_ptt
	n_args[15] = 0; // cfork
	n_args[16] = 4; // mmap
	n_args[17] = 2; // munmap
	n_args[18] = 3; // mprotect
	n_args[19] = 1; // pmap
	n_args[20] = 0; // vfork
	n_args[21] = 0; // get_user_p
	n_args[22] = 0; // get_cow_f
	n_args[23] = 2; // open
	n_args[24] = 3; // read
	n_args[25] = 3; // write
	n_args[27] = 1; // dup
	n_args[28] = 2; // dup2
	n_args[29] = 1; // close
	n_args[30] = 3; // lseek
	n_args[35] = 4; // ftrace
	n_args[36] = 1; // trace_buffer
	n_args[37] = 2; // start_strace
	n_args[38] = 0; // end_strace
	n_args[39] = 3; // read_strace
	n_args[40] = 2; // strace
	n_args[41] = 3; // read_ftrace
	// n_args[61] = ; // getppid
	return n_args[syscall_num];
}

int perform_tracing(u64 syscall_num, u64 param1, u64 param2, u64 param3, u64 param4)
{
	if(syscall_num == SYSCALL_END_STRACE){
		return 0;
	}
	struct exec_context *ctx = get_current_ctx();
	struct strace_head *st_md_base = ctx->st_md_base;
	if(st_md_base == NULL){
		ctx->st_md_base = (struct strace_head*)os_alloc(sizeof(struct strace_head));
		st_md_base = ctx->st_md_base;
		st_md_base->count = 0;
		st_md_base->is_traced = 0;
		st_md_base->next = NULL;
		st_md_base->last = NULL;
		return 0;
	}
	if(st_md_base->is_traced == 0){
		return 0;
	}
	int fd = st_md_base->strace_fd;
	struct file *filep = ctx->files[fd];
	int tracing_mode = st_md_base->tracing_mode;
	if(tracing_mode == FILTERED_TRACING){
		struct strace_info *ptr = st_md_base->next;
		while(ptr != NULL && ptr->syscall_num != syscall_num){
			ptr = ptr->next;
		}
		if(ptr == NULL){
			return 0;
		}
	}
	int n_args = get_n_args(syscall_num);
	int ret;
	ret = trace_buffer_write_helper(filep, &syscall_num, 8);
	if(n_args >= 1){
		trace_buffer_write_helper(filep, &param1, 8);
	}
	if(n_args >= 2){
		trace_buffer_write_helper(filep, &param2, 8);
	}
	if(n_args >= 3){
		trace_buffer_write_helper(filep, &param3, 8);
	}
	if(n_args >= 4){
		trace_buffer_write_helper(filep, &param4, 8);
	}
	return 0;
}

struct strace_info* find_snode(struct strace_info *head, int syscall_num){
	struct strace_info *ptr = head;
	while(ptr != NULL && ptr->syscall_num != syscall_num){
		ptr = ptr->next;
	}
	return ptr;
}

int sys_strace(struct exec_context *current, int syscall_num, int action)
{
	if(current == NULL){
		return -EINVAL;
	}
	if(action != ADD_STRACE && action != REMOVE_STRACE){
		return -EINVAL;
	}
	struct strace_head *st_md_base = current->st_md_base;
	if(st_md_base == NULL){
		current->st_md_base = (struct strace_head*)os_alloc(sizeof(struct strace_head));
		if(current->st_md_base == NULL){
			return -EINVAL;
		}
		st_md_base = current->st_md_base;
		st_md_base->count = 0;
		st_md_base->is_traced = 0;
		st_md_base->next = NULL;
		st_md_base->last = NULL;
	}
	if(action == ADD_STRACE){
		if(st_md_base->count == STRACE_MAX){
			return -EINVAL;
		}
		struct strace_info *ptr = find_snode(st_md_base->next, syscall_num);
		if(ptr != NULL){
			return -EINVAL;
		}
		ptr = (struct strace_info*)os_alloc(sizeof(struct strace_info));
		if(ptr == NULL){
			return -EINVAL;
		}
		ptr->syscall_num = syscall_num;
		ptr->next = NULL;
		if(st_md_base->count == 0){
			st_md_base->next = st_md_base->last = ptr;
		}
		else{
			st_md_base->last->next = ptr;
			st_md_base->last = ptr;
		}
		st_md_base->count++;
	}
	else{
		if(st_md_base->count == 0){
			return -EINVAL;
		}
		struct strace_info *ptr = find_snode(st_md_base->next, syscall_num);
		if(ptr == NULL){
			return -EINVAL;
		}
		if(st_md_base->count == 1){
			os_free(ptr, sizeof(struct strace_info));
			st_md_base->next = NULL;
			st_md_base->last = NULL;
			st_md_base->count = 0;
			return 0;
		}
		if(st_md_base->next == ptr){
			st_md_base->next = ptr->next;
			os_free(ptr, sizeof(struct strace_info));
			st_md_base->count--;
			return 0;
		}
		struct strace_info *prev = st_md_base->next;
		while(prev->next != ptr){
			prev = prev->next;
		}
		prev->next = ptr->next;
		if(ptr->next == NULL){
			st_md_base->last = prev;
		}
		os_free(ptr, sizeof(struct strace_info));
		st_md_base->count--;
	}
	return 0;
}

int sys_read_strace(struct file *filep, char *buff, u64 count)
{
	if(filep == NULL || count < 0){
		return -EINVAL;
	}
	if(count == 0){
		return 0;
	}
	int i = 0;
	while(count--){
		u64 temp;
		int ret_val = trace_buffer_read_helper(filep, &temp, 8);
		if(ret_val < 0){
			return -EINVAL;
		}
		if(ret_val < 8){
			return i;
		}
		u8 *_temp = &temp;
		for(int j = 0; j < 8; j++){
			buff[i] = *(_temp);
			i++;
			_temp++;
		}
		int n_args = get_n_args(temp);
		while(n_args--){
			ret_val = trace_buffer_read_helper(filep, &temp, 8);
			if(ret_val < 8){
				return -EINVAL;
			}
			_temp = &temp;
			for(int j = 0; j < 8; j++){
				buff[i] = *(_temp);
				i++;
				_temp++;
			}
		}
	}
	return i;
}

int sys_start_strace(struct exec_context *current, int fd, int tracing_mode)
{
	if(current == NULL){
		return -EINVAL;
	}
	if(tracing_mode != FULL_TRACING && tracing_mode != FILTERED_TRACING){
		return -EINVAL;
	}
	struct strace_head *st_md_base = current->st_md_base;
	if(st_md_base == NULL){
		current->st_md_base = (struct strace_head*)os_alloc(sizeof(struct strace_head));
		if(current->st_md_base == NULL){
			return -EINVAL;
		}
		st_md_base = current->st_md_base;
		st_md_base->count = 0;
		st_md_base->next = NULL;
		st_md_base->last = NULL;
	}
	st_md_base->is_traced = 1;
	st_md_base->strace_fd = fd;
	st_md_base->tracing_mode = tracing_mode;
	return 0;
}

int sys_end_strace(struct exec_context *current)
{
	if(current == NULL){
		return -EINVAL;
	}
	struct strace_head *st_md_base = current->st_md_base;
	if(st_md_base == NULL){
		return -EINVAL;
	}
	struct strace_info *ptr = st_md_base->next;
	while(ptr != NULL){
		struct strace_info *ptr_next = ptr->next;
		os_free(ptr, sizeof(struct strace_info));
		ptr = ptr_next;
	}
	st_md_base->count = 0;
	st_md_base->is_traced = 0;
	st_md_base->next = NULL;
	st_md_base->last = NULL;
	os_free(current->st_md_base, sizeof(struct strace_head));
	current->st_md_base = NULL;
	return 0;
}

///////////////////////////////////////////////////////////////////////////
//// 		Start of ftrace functionality 		      	      /////
///////////////////////////////////////////////////////////////////////////

struct ftrace_info* find_fnode(struct ftrace_info *head, unsigned long faddr){
	struct ftrace_info *ptr = head;
	while(ptr != NULL && ptr->faddr != faddr){
		ptr = ptr->next;
	}
	return ptr;
}

long do_ftrace(struct exec_context *ctx, unsigned long faddr, long action, long nargs, int fd_trace_buffer)
{
	if(ctx == NULL){
		return -EINVAL;
	}
	struct ftrace_head *ft_md_base = ctx->ft_md_base;
	if(ft_md_base == NULL){
		ctx->ft_md_base = (struct ftrace_head*)os_alloc(sizeof(struct ftrace_head));
		if(ctx->ft_md_base == NULL){
			return -EINVAL;
		}
		ft_md_base = ctx->ft_md_base;
		ft_md_base->count = 0;
		ft_md_base->next = NULL;
		ft_md_base->last = NULL;
	}
	if(action == ADD_FTRACE){
		if(ft_md_base->count == FTRACE_MAX){
			return -EINVAL;
		}
		struct ftrace_info *ptr = find_fnode(ft_md_base->next, faddr);
		if(ptr != NULL){
			return -EINVAL;
		}
		ptr = (struct ftrace_info*)os_alloc(sizeof(struct ftrace_info));
		if(ptr == NULL){
			return -EINVAL;
		}
		ptr->faddr = faddr;
		ptr->num_args = nargs;
		ptr->fd = fd_trace_buffer;
		ptr->capture_backtrace = 0;
		ptr->next = NULL;
		if(ft_md_base->count == 0){
			ft_md_base->next = ft_md_base->last = ptr;
		}
		else{
			ft_md_base->last->next = ptr;
			ft_md_base->last = ptr;
		}
		ft_md_base->count++;
	}
	else if(action == REMOVE_FTRACE){
		if(ft_md_base->count == 0){
			return -EINVAL;
		}
		struct ftrace_info *ptr = find_fnode(ft_md_base->next, faddr);
		if(ptr == NULL){
			return -EINVAL;
		}
		u32 *temp = faddr;
		if(*temp == 0xFFFFFFFF){
			do_ftrace(ctx, faddr, DISABLE_FTRACE, nargs, fd_trace_buffer);
		}
		if(ft_md_base->count == 1){
			os_free(ptr, sizeof(struct ftrace_info));
			ft_md_base->next = NULL;
			ft_md_base->last = NULL;
			ft_md_base->count = 0;
			return 0;
		}
		if(ft_md_base->next == ptr){
			ft_md_base->next = ptr->next;
			os_free(ptr, sizeof(struct ftrace_info));
			ft_md_base->count--;
			return 0;
		}
		struct ftrace_info *prev = ft_md_base->next;
		while(prev->next != ptr){
			prev = prev->next;
		}
		prev->next = ptr->next;
		if(ptr->next == NULL){
			ft_md_base->last = prev;
		}
		os_free(ptr, sizeof(struct ftrace_info));
		ft_md_base->count--;
	}
	else if(action == ENABLE_FTRACE){
		struct ftrace_info *ptr = find_fnode(ft_md_base->next, faddr);
		if(ptr == NULL){
			return -EINVAL;
		}
		u32 *temp = faddr;
		if(*temp == 0xFFFFFFFF){
			return 0;
		}
		u8 *instruction = faddr;
		ptr->code_backup[0] = *instruction;
		*instruction = 0xFF;
		ptr->code_backup[1] = *(instruction + 1);
		*(instruction + 1) = 0xFF;
		ptr->code_backup[2] = *(instruction + 2);
		*(instruction + 2) = 0xFF;
		ptr->code_backup[3] = *(instruction + 3);
		*(instruction + 3) = 0xFF;
	}
	else if(action == DISABLE_FTRACE){
		struct ftrace_info *ptr = find_fnode(ft_md_base->next, faddr);
		if(ptr == NULL){
			return -EINVAL;
		}
		u32 *temp = faddr;
		if(*temp != 0xFFFFFFFF){
			return 0;
		}
		u8 *instruction = faddr;
		*instruction = ptr->code_backup[0];
		*(instruction + 1) = ptr->code_backup[1];
		*(instruction + 2) = ptr->code_backup[2];
		*(instruction + 3) = ptr->code_backup[3];
	}
	else if(action == ENABLE_BACKTRACE){
		struct ftrace_info *ptr = find_fnode(ft_md_base->next, faddr);
		if(ptr == NULL){
			return -EINVAL;
		}
		u32 *temp = faddr;
		if(*temp != 0xFFFFFFFF){
			do_ftrace(ctx, faddr, ENABLE_FTRACE, nargs, fd_trace_buffer);
		}
		ptr->capture_backtrace = 1;
	}
	else if(action == DISABLE_BACKTRACE){
		struct ftrace_info *ptr = find_fnode(ft_md_base->next, faddr);
		if(ptr != NULL){
			return -EINVAL;
		}
		u32 *temp = faddr;
		if(*temp == 0xFFFFFFFF){
			do_ftrace(ctx, faddr, DISABLE_FTRACE, nargs, fd_trace_buffer);
		}
		ptr->capture_backtrace = 0;
	}
	else{
		return -EINVAL;
	}
    return 0;
}

long handle_ftrace_fault(struct user_regs *regs)
{
	struct exec_context *ctx = get_current_ctx();
	struct ftrace_head *ft_md_base = ctx->ft_md_base;
	if(ft_md_base == NULL){
		return -EINVAL;
	}
	unsigned long faddr = regs->entry_rip;
	struct ftrace_info *ptr = find_fnode(ft_md_base->next, faddr);
	if(ptr == NULL){
		return -EINVAL;
	}
	u32 num_args = ptr->num_args;
	int fd = ptr->fd;
	int capture_backtrace = ptr->capture_backtrace;
	struct file **files = ctx->files;
	if(files == NULL){
		return -EINVAL;
	}
	struct file *filep = files[fd];
	if(filep == NULL){
		return -EINVAL;
	}
	trace_buffer_write_helper(filep, &faddr, 8);
	if(num_args >= 1){
		trace_buffer_write_helper(filep, &(regs->rdi), 8);
	}
	if(num_args >= 2){
		trace_buffer_write_helper(filep, &(regs->rsi), 8);
	}
	if(num_args >= 3){
		trace_buffer_write_helper(filep, &(regs->rdx), 8);
	}
	if(num_args >= 4){
		trace_buffer_write_helper(filep, &(regs->rcx), 8);
	}
	if(num_args >= 5){
		trace_buffer_write_helper(filep, &(regs->r8), 8);
	}
	if(num_args >= 6){
		trace_buffer_write_helper(filep, &(regs->r9), 8);
	}
	regs->entry_rsp = regs->entry_rsp - 8;
	*((u64*)regs->entry_rsp) = regs->rbp;
	regs->rbp = regs->entry_rsp;
	regs->entry_rip = regs->entry_rip + 4;
	if(capture_backtrace == 1){
		trace_buffer_write_helper(filep, &faddr, 8);
		u64 *ptr = regs->rbp;
		u64 ret_addr = *(ptr + 1);
		while(ret_addr != END_ADDR){
			trace_buffer_write_helper(filep, &ret_addr, 8);
			ptr = *ptr;
			ret_addr = *(ptr + 1);
		}
	}
	u64 delimiter = 0x0123456789ABCDEF;
	trace_buffer_write_helper(filep, &delimiter, 8);
    return 0;
}

int sys_read_ftrace(struct file *filep, char *buff, u64 count)
{
	if(filep == NULL || count < 0){
		return -EINVAL;
	}
	if(count == 0){
		return 0;
	}
	int type = filep->type;
	int mode = filep->mode;
	if(type != TRACE_BUFFER){
		return -EINVAL;
	}
	int i = 0;
	while(count--){
		u64 temp;
		int ret_val = trace_buffer_read_helper(filep, &temp, 8);
		if(ret_val < 0){
			return -EINVAL;
		}
		if(ret_val < 8){
			return i;
		}
		u64 delimiter = 0x0123456789ABCDEF;
		while(temp != delimiter){
			u8 *_temp = &temp;
			int j = 8;
			while(j--){
				buff[i] = *(_temp);
				i++;
				_temp++;
			}
			int ret_val = trace_buffer_read_helper(filep, &temp, 8);
			if(ret_val < 8){
				return -EINVAL;
			}
		}
	}
	return i;
}
