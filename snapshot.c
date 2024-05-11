#include<stdio.h>
#include<string.h>
#include<dirent.h>
#include<sys/stat.h>
#include <sys/wait.h>
#include<stdlib.h>
#include<unistd.h>
#define NAME_LEN 256
#define MAX_EL 1000

typedef struct{
    char file[NAME_LEN];
    int inode;
    int size;
    int tip;
}snapEnt;

int isDir(char* name){
    struct stat aux;
    return (stat(name,&aux)==0) && S_ISDIR(aux.st_mode);
}

int isTxt(char* name){
    int len = strlen(name);
    return (len>=4) && (strcmp(name + len - 4, ".txt") == 0);
}

int uploadSnapshot(snapEnt* oldSnap, FILE* snp){
    int i=0;
    for(i=0;;i++){
        if(fscanf(snp,"%d;%256[^;];%d;%d\n",&oldSnap[i].tip,oldSnap[i].file,&oldSnap[i].inode,&oldSnap[i].size)!=4){
            i--;
            break;
        }
    }
    return i;
}

int noAccess(struct stat aux){
    mode_t permissions=S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH;
    return !(aux.st_mode & permissions);
}

int dangerous(char* name){
    char command[2*NAME_LEN];
    snprintf(command,sizeof(command),"./verify_dangerous.sh %s",name);
    FILE *pipe = popen(command, "r");
    if(pipe==NULL){
        perror("pipe failed");
        exit(-7);
    }
    char result[NAME_LEN];
    fscanf(pipe,"%s",result);
    if(pclose(pipe)==-1){
        perror("failed closing pipe");
        exit(-10);
    }
    return strcmp(result,"SAFE");
}

int snapshot(snapEnt* newSnap, char* name, int *corr, char *isolated){
    DIR* dir=opendir(name);
    int corrupted=0;
    if(dir==NULL){
        perror("failed opening directory");
        exit(-4);
    }

    struct dirent* entry;
    char path[NAME_LEN];
    char newPath[NAME_LEN];
    int i=0,j=0;
    for(i=0;entry=readdir(dir);i++){
        j=-1;
        if(strcmp(entry->d_name,".")==0 || strcmp(entry->d_name,"..")==0){
            i--;
            continue;
        }
        snprintf(path,sizeof(path),"%s/%s",name,entry->d_name);
        struct stat aux;
        if(stat(path,&aux)!=0){
            perror("failed to verify path");
            exit(-2);
        }
        if(isTxt(path) && noAccess(aux) && dangerous(path)){
            snprintf(newPath,sizeof(newPath),"%s/%s",isolated,entry->d_name);
            if (rename(path, newPath) != 0) {
                perror("couldn't move corrupted file");
                exit(-11);
            }
            i--;
            corrupted++;
            continue;
        }
        strcpy(newSnap[i].file,path);
        newSnap[i].inode=aux.st_ino;
        newSnap[i].size=aux.st_size;
        if(isDir(newSnap[i].file)){
            DIR* subdir=opendir(newSnap[i].file);
            if(subdir==NULL){
                perror("failed opening directory");
                exit(-4);
            }
            struct dirent* subEnt;
            for(j=0;subEnt=readdir(subdir);j++){
                if(strcmp(subEnt->d_name,".")==0 || strcmp(subEnt->d_name,"..")==0){
                    j--;
                    continue;
                }
                snprintf(path,sizeof(path),"%s/%s",newSnap[i].file,subEnt->d_name);
                if(stat(path,&aux)!=0){
                    perror("failed to verify path");
                    exit(-2);
                }
                if(isTxt(path) && noAccess(aux) && dangerous(path)){
                    snprintf(newPath,sizeof(newPath),"%s/%s",isolated,subEnt->d_name);
                    if (rename(path, newPath) != 0) {
                        perror("couldn't move corrupted file");
                        exit(-11);
                    }
                    j--;
                    corrupted++;
                    continue;
                }
                strcpy(newSnap[i+j+1].file,path);
                newSnap[i+j+1].inode=aux.st_ino;
                newSnap[i+j+1].size=aux.st_size;
                newSnap[i+j+1].tip=(isDir(newSnap[i+j+1].file))? 0:-1;
            }
            if(closedir(subdir)!=0){
                perror("failed closing directory");
                exit(-5);
            }
        }
        newSnap[i].tip=j;
        if(j>=0) i+=j;
    }

    if(closedir(dir)!=0){
        perror("failed closing directory");
        exit(-5);
    }
    *corr=corrupted;
    return i;
}

int inVect(snapEnt x, snapEnt* vect, int n, int *renamed, int *sizeMod, int *index){
    for(int i=0;i<n;i++){
        if(x.inode==vect[i].inode){
            *renamed=strcmp(x.file,vect[i].file);
            *sizeMod=!(x.size==vect[i].size);
            *index=i;
            return 1;
        }
    }
    *renamed=0;
    *sizeMod=0;
    *index=-1;
    return 0;
}

void changes(snapEnt* new, int n1, snapEnt* old, int n2){
    int renamed=0, sizeMod=0, index=-1;
    FILE* out = fopen("changes.txt","w");
    if(out==NULL){
        perror("failed opening file");
        exit(-8);
    }
    for(int i=0;i<n1;i++){
        int j=0;
        if(!inVect(new[i],old,n2,&renamed,&sizeMod,&index)){
            if(isDir(new[i].file)){
                fprintf(out,"Directory %s added, containing the %d items:\n",new[i].file,new[i].tip);
                for(j=1;j<=new[i].tip;j++){
                    printf("\t%s\n",new[i+j].file);
                }
                j--;
            }
            else fprintf(out,"File %s added\n",new[i].file);
            i+=j;
        }
        else{
            if(renamed) fprintf(out,"Item %s was renamed to %s\n",old[index].file,new[i].file);
            if(sizeMod) fprintf(out,"The size of item %s changed from %d bytes to %d bytes\n",new[i].file,old[index].size,new[i].size);
        }
    }
    for(int i=0;i<n2;i++){
        if(!inVect(old[i],new,n1,&renamed,&sizeMod,&index)){
            if(old[i].tip>=0){
                fprintf(out,"Directory %s was removed\n",old[i].file);
                i+=old[i].tip;
            }
            else fprintf(out,"File %s removed\n",old[i].file);
        }
    }
    if(fclose(out)!=0){
        perror("failed closing file");
        exit(-9);
    }
}

void updateSnapshot(snapEnt* new, int n, FILE* old){
    for(int i=0;i<n;i++){
        fprintf(old,"%d;%s;%d;%d\n",new[i].tip,new[i].file,new[i].inode,new[i].size);
    }
}

int hasSnap(char* name, char* snapDir, char* reference){
    struct stat aux;
    if(stat(name,&aux)!=0){
        perror("failed to verify path");
        exit(-2);
    }
    char snap[NAME_LEN];
    snprintf(snap, sizeof(snap), "%d.txt", aux.st_ino);
    snprintf(reference, sizeof(char)*NAME_LEN, "%s/%s", snapDir, snap);
    DIR* dir=opendir(snapDir);
    if(dir==NULL){
        perror("failed opening directory");
        exit(-4);
    }

    struct dirent* entry;
    int retValue=0;
    while(entry=readdir(dir)){
        if(strcmp(entry->d_name,snap)==0){
            retValue=1;
            break;
        }
    }
    if(closedir(dir)!=0){
        perror("failed closing directory");
        exit(-5);
    }
    return retValue;
}

int processDir(char* dir, char* snapDir, char* isolated){
    char ref[NAME_LEN];
    int corrupted=0;
    int flag=hasSnap(dir,snapDir,ref);
    snapEnt new[MAX_EL];
    int n1=snapshot(new,dir,&corrupted,isolated);
    if(flag==0){
        changes(new,n1,NULL,0);
    }
    else{
        FILE* aux = fopen(ref,"r");
        if(aux==NULL){
            perror("failed opening file");
            exit(-8);
        }
        snapEnt old[MAX_EL];
        int n2=uploadSnapshot(old,aux);
        if(fclose(aux)!=0){
            perror("failed closing file");
            exit(-9);
        }
        changes(new,n1,old,n2);
    }
    FILE* aux1 = fopen(ref,"w");
    if(aux1==NULL){
        perror("failed opening file");
        exit(-8);
    }
    updateSnapshot(new,n1,aux1);
    if(fclose(aux1)!=0){
        perror("failed closing file");
        exit(-9);
    }
    return corrupted;
}

void addSnapDir(char *directoryName){
    int status = mkdir(directoryName, 0777);
    if (status!=0) {
        perror("Error creating directory");
        exit(-6);
    }
}

int main(int argc, char* argv[]){
    if(argc<5){
        perror("incorrect number of arguments");
        return -1;
    }
    if(isDir(argv[2])==0){
        addSnapDir(argv[2]);
    }
    int i, cp=0, status;
    pid_t pid;
    for(i=5;i<argc;i++){
        if(isDir(argv[i])){
            pid=fork();
            if(pid<0){
                perror("fork failed");
                exit(-3);
            }
            cp++;
            if(pid==0){
                int st=processDir(argv[i],argv[2],argv[4]);
                printf("Snapshot for directory %s created successfully %d\n", argv[i],st);
                exit(st);
            }
        }
    }
    for(int j=0;j<cp;j++){
        pid=wait(&status);
        if(status<0) printf("Child process with PID %d exited with status: %d\n", pid, WEXITSTATUS(status));
        else printf("Child process with PID %d ended with %d potentially dangerous files\n", pid, WEXITSTATUS(status));
    }
    return 0;
}