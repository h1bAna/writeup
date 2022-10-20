// g++ -o pwn-cpp-type-confusion pwn-cpp-type-confusion.cpp

#include <iostream>
#include <csignal>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

int appleflag = 0;
int mangoflag = 0;
int applemangoflag = 0;

void getshell(){
    system("/bin/sh");
}

void print_menu(){
    std::cout << "I love Applemango!" << std::endl;
    std::cout << "1. Make apple" << std::endl;
    std::cout << "2. Make mango" << std::endl;
    std::cout << "3. Mix apple, mango" << std::endl;
    std::cout << "4. Eat" << std::endl;
    std::cout << "5. Exit program" << std::endl;
    std::cout << "[*] Select : ";
}
void alarm_handler(int trash)
{
    std::cout << "TIME OUT" << std::endl;
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void mangohi(){
    std::cout << "Mangoyum" << std::endl;
}

void applehi(){
    std::cout << "Appleyum" << std::endl;
}

class Base{
public:
    virtual void yum(){
    }
};

class Apple : public Base{
public:
    virtual void yum(){
        std::cout << description << std::endl;
    }
    Apple(){
        strcpy(description, "Appleyum\x00");
        appleflag = 1;
    };

    ~Apple(){
        appleflag = 0;
    }
    char description[8];
};

class Mango : public Base{
public:
    virtual void yum(){
        description();
    }

    Mango(){
        description = mangohi;
        mangoflag = 1;
    };

    ~Mango(){
        mangoflag = 0;
    }
    void (*description)(void);
};



int main(){
    initialize();
    int selector;
    std::string applemangoname;
    Base *apple;
    Base *mango;
    Apple* mixer;

    while(1){
        print_menu();
        std::cin >> selector;
        switch(selector){
            case 1:
                apple = new Apple();
                std::cout << "Apple Created!" << std::endl;
                break;
            case 2:
                mango = new Mango();
                std::cout << "Mango Created!" << std::endl;
                break;
            case 3:
                if(appleflag && mangoflag){
                    applemangoflag = 1;
                    mixer = static_cast<Apple*>(mango);
                    std::cout << "Applemango name: ";
                    std::cin >> applemangoname;
                    strncpy(mixer->description, applemangoname.c_str(), 8);
                    std::cout << "Applemango Created!" << std::endl;
                } else if(appleflag == 0 && mangoflag == 0){
                    std::cout << "You don't have anything!" << std::endl;
                } else if(appleflag == 0){
                    std::cout << "You don't have apple!" << std::endl;
                } else if(mangoflag == 0){
                    std::cout << "You don't have mango!" << std::endl;
                }
                break;
            case 4:
                std::cout << "1. Apple\n2. Mango\n3. Applemango\n[*] Select : ";
                std::cin >> selector;
                if(selector == 1){
                    if(appleflag){ 
                        apple->yum(); 
                    }
                    else{ std::cout << "You don't have apple!" << std::endl; }
                } else if (selector == 2){
                    if(mangoflag){ 
                        mango->yum(); 
                    }
                    else{ 
                        std::cout << "you don't have mango!" << std::endl; 
                    }
                } else if (selector == 3){
                    if(applemangoflag) { 
                        mixer->yum(); 
                    }
                    else{ 
                        std::cout << "you don't have Applemango!" << std::endl; 
                    }
                } else {
                    std::cout << "Wrong Choice!" << std::endl;
                }
                break;
            case 5:
                std::cout << "bye!" << std::endl;
                return 0;
                break;
            default:
                return 0;
        }
    }
    return 0;    
}