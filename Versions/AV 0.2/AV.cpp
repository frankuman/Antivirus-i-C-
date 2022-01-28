//Gjort av Oliver Bölin & Oskar Hansson
//Kurskod 1620
//Startdatum 24/01/2022


//Version 0.4


//Includes
#include <iostream>
#include <string>
#include <fstream> 
#include <vector>
#include <iomanip>
#include <dirent.h> //opendir() 
#include <libgen.h>
using namespace std;


//Iterates thru mapes, tiny bit buggy (0.2)
vector<string> find_subdirs(const char *current_directory, vector<string> &sus_files_container, string directory){
    
    if (auto dir = opendir(current_directory)){
        while (auto f = readdir(dir)){ 
            if (!f->d_name || f->d_name[0] == '.' || !dir){
                //Dont know what to do here, it works with nothing
            }
            else{
                string subdirpath = directory + "/" + f->d_name; //We still need to create a path
                const char *c_directory = subdirpath.c_str(); //It needs to be const char * (?)
                if(opendir(c_directory) == NULL){
                    sus_files_container.push_back(subdirpath);
                }
                find_subdirs(c_directory, sus_files_container, subdirpath);
            }
        }
        closedir(dir);
    }
    return sus_files_container;
}
//Is supposed to compare the signatures to the sussy files
void compare_file(string &sus_file){
    
}
//Is supposed to create the hexadecimal for the files (?)
string check_file(string &sus_file){
    
    ifstream infile(sus_file, ios_base::binary);
    const int lenght = 10;
    unsigned char bytes[lenght];
    
    if (infile.read(reinterpret_cast<char*>(bytes),lenght)){
        size_t numRead = infile.gcount(); //This line idk
        ostringstream oss;
        for(auto j = 0; j < numRead; j++){
            oss << hex << setw(2) << setfill('0') << static_cast<unsigned short>(bytes[j]); //This line idk
        }
        string hex_data = oss.str();
        return hex_data;
        
    }

}
//Finds the signatures (If they're in the same dictionary as the program) and puts them into a container
vector<string> find_signatures(vector<string> &signature_container){
    string line;
    
    ifstream signatures;
    signatures.open("signatures.db");

    if(signatures.is_open()){
        while(getline(signatures,line)){
            signature_container.push_back(line);
        }
    }   signatures.close();
    return signature_container;
}

//Main
int main(){
    std::cout << "Virus Detection System\n";
    string directory = "/home/olive/Desktop/TestDir";
    vector<string> signature_container; //Stores all the signatures from DB
    vector<string> sus_files_container; //Stores all the names of the files
    vector<string> hex_container; //Stores all the hexadecimal hashes of the files

    const char *c_directory = directory.c_str();
    find_signatures(signature_container); //To find the signatures from DB
    find_subdirs(c_directory, sus_files_container, directory); //To find the directories and files
    for(auto i = 0; i < sus_files_container.size(); i++){ //Take each file and check their hex
        hex_container.push_back(check_file(sus_files_container.at(i))); 
    }
    
    for(auto i = 0; i < hex_container.size(); i++){ // Just to print out hex for the files found
        cout << hex_container.at(i) << endl; //
    }


    return 0;
}
