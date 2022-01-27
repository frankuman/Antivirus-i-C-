//Gjort av Oliver Bölin & Oskar Hansson
//Kurskod 1620
//Startdatum 24/01/2022


//Version 0.1.2


//Includes
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <dirent.h> //opendir() 
#include <libgen.h>
using namespace std;

///home/olive/Desktop/TestDir

//Iterates thru mapes, still a bit buggy (0.1.2)
vector<string> find_subdirs(const char *current_directory, vector<string> &sub_dirs, string directory){
    
    if (auto dir = opendir(current_directory)){
        while (auto f = readdir(dir)){
            if (!f->d_name || f->d_name[0] == '.'){
                printf("File: %s\n", f->d_name);
            }
            else{
                sub_dirs.push_back(f->d_name);
                printf("Directory: %s\n", f->d_name);
                string subdirpath = directory + "/" + f->d_name;
                cout << "PATH: " + subdirpath << endl;
                const char *c_directory = subdirpath.c_str();
                find_subdirs(c_directory, sub_dirs, subdirpath);
            }
        }
        closedir(dir);
    }
    return sub_dirs;
}
int main(){
    std::cout << "Virus Detection System\n";
    string directory = "/home/olive/Desktop/TestDir";
    //cin >> directory;
    const char *c_directory = directory.c_str();
    vector<string> sub_dirs;
    find_subdirs(c_directory, sub_dirs, directory);







    return 0;
}
