#include<stdio.h> 
#include <unistd.h> 
#include <stdlib.h> 
#define num 80
void *chunk_list[num];
int chunk_size[num];

void init()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

void menu()
{
    puts("1.add");
    puts("2.edit");
    puts("3.show");
    puts("4.delete");
    puts("5.exit");
    puts("Your choice:");
}


int add()
{
    int index,size;
    puts("index:");
    scanf("%d",&index);
    puts("Size:");
    scanf("%d",&size);
    chunk_list[index] = malloc(size);
    chunk_size[index] = size;
}

int edit()
{
    int size;
    int index;
    puts("index:");
    scanf("%d",&index);
    puts("size:");
    scanf("%d",&size);
    puts("context: ");
    read(0,chunk_list[index],size);
}

int delete()
{
    int index;
    puts("index:");
    scanf("%d",&index);
    free(chunk_list[index]);
}

int show()
{
    int index;
    puts("index:");
    scanf("%d",&index);
    puts("context: ");
    puts(chunk_list[index]);
}


int main()
{
    int choice;
    init();
    while(1){
        menu();
        scanf("%d",&choice);
        if(choice==5){
            exit(0);
        }
        else if(choice==1){
            add();
        }
        else if(choice==2){
            delete();
        }
        else if(choice==3){
            edit();
        }
        else if(choice==4){
            show();
        }
        }
}
