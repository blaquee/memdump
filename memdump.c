#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct heap
{
	void *address;
	void *saddress;
	int size;
};

long peekdata(void *addr, int pid) 
{
  return ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
}

int attach_pid(int pid_id)
{
	pid_t proc_traced = 0;
	ptrace(PTRACE_ATTACH, proc_traced, NULL, NULL);
	wait(NULL);
	if(proc_traced != 0) {
		return proc_traced;
	} else {
		return -1;
	}
}

int dump_heap(struct heap **heap_dump, int pid_id)
{
	if(attach_pid(pid_id) == 0) {
		printf("* Error attaching to process [%d].\n",pid_id);
		return 1;
	}

	
	return 0;
}

struct heap** find_heap_values(int pid_id)
{
	struct heap **heaps = (struct heap**)malloc(sizeof(struct heap**));
	int i,heap_size = 0;	
	char *end;
	char pid_map[30];
	char *heap_loc, *heap_end;
	char data[1024];
	FILE *map;
	
	sprintf(pid_map,"/proc/%d/maps",pid_id);
	map = fopen(pid_map,"r");
	if(map == NULL) {
		printf("* Error, unable to read process [%d] file map.\n",pid_id);
		exit(1);
	}
 
	printf("* Attempting to find process [%d] heap location(s).\n",pid_id);
	while(fgets(data, 1024, map) != NULL) {
		if(strstr(data, "[heap]") != NULL) {
			heaps[heap_size] = (struct heap*)malloc(sizeof(struct heap*));
			heap_loc = strtok(data,"-");
			if((strcmp(heap_loc,"")) == 0) {
				printf("* Error finding heap addresses.\n");
				exit(1);
			}

			heaps[heap_size]->saddress = (void *)strtol(heap_loc,&end,16);
			printf("[heap] start:0x%s ",heap_loc);
			heap_loc = strtok(NULL,"- ");
			printf("end:0x%s ",heap_loc);
			heaps[heap_size]->address = (void *)strtol(heap_loc,&end,16);
			heaps[heap_size]->size = (int)(heaps[heap_size]->address - heaps[heap_size]->saddress);
			printf("size=%d\n",heaps[heap_size]->size);
			heap_size++;
			heaps = realloc(heaps, heap_size*sizeof(struct heap*));
		}
	}

	fclose(map);
	for(i=0; i<heap_size; i++) {
		free(heaps[i]);
	}
	free(heaps);
	return heaps;
}


int main(int argc, char *argv[])
{
	struct heap **heap_dump = NULL;
	int proc_pid = 0;

        printf("memory dumper version 1.0.1\n");
        printf("--------------------------------------------------------------\n");

	if(argc != 2) {
		printf("usage %s PID\n",argv[0]);
		exit(1);
	} else {
		proc_pid = atoi(argv[1]);
	}

	heap_dump = find_heap_values(proc_pid);
	if(heap_dump != NULL) {
		dump_heap(heap_dump,proc_pid);
	} else {
		printf("* Unknown error occured.\n");
	}
	return 0;
}	
