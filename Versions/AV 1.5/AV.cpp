//Gjort av Oliver Bölin
//Oliverbolin97@gmail.com
//Kurskod 1620
//Startdatum 24/01/2022


//Version 1.5


//Includes & Colours
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#include <iostream>
#include <string>
#include <fstream> 
#include <vector>
#include <iomanip>
#include <dirent.h> //opendir() 
#include <libgen.h>
#include <unistd.h>
using namespace std;
//prints help functions
void help(){
    cout << GREEN <<"\n-------------HELP-------------\n";
    cout << RED << "[Commandlist]\n[1] path to directory to start the search \n[2] -f for full hex in logs \n[3] -d [DIRECTORY] to specify a signature database followed up by path\n[4] -b [DIRECTORY] to specify a directory that should never be scanned\n[5] -c To clear the blocklist" << endl;
}
//Checks if directory is in blocked, returns true if legal or false
bool check_blocked(string directory){
    ifstream check;
    string line;
    check.open("blocked.txt");
    if(check.is_open()){
        while(getline(check,line)){
            if(line == directory){
                cout << MAGENTA <<"\n[*] ERROR\n";
                cout << MAGENTA <<"\n[*] Access to those directories are not allowed" << endl;
                return false;
            }
        }
    }
    return true;
}
//Checks the input (string) and returns true if the inputs are legal
bool input_validation(string arg1){

    if(arg1 == "/etc/hosts" || arg1 == "/etc/shadow" || arg1 == "/etc/passwd" || arg1 == "/etc/group" || arg1 == "/etc/gshadow" || arg1 == "/etc/pam.d"){
        cout << MAGENTA <<"\n[*] ERROR\n";
        cout << MAGENTA <<"\n[*] Access to those directories are not allowed" << endl;
        return false;
    }
    return true;
}
//Iterates thru directories and returns a container filled with the paths to files
vector<string> find_subdirs(const char *current_directory, vector<string> &sus_files_container, string directory){
    
    if(input_validation(directory) == false || check_blocked(directory) == false)
          return(sus_files_container);      
    if (auto dir = opendir(current_directory)){
        while (auto f = readdir(dir)){ 
            if (!f->d_name || f->d_name[0] == '.' || !dir){
            }
            else{
                string subdirpath = directory + "/" + f->d_name; 
                const char *c_directory = subdirpath.c_str(); 
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
//Compares two hexcontainers, and prints into the logs if they match
void compare_hex(vector<string>& hex, vector<string>& signatures, vector<string>& file_names, bool& fullinfo){
    ofstream logs("dv1620log.txt");
    int virus_counter = 0;

    for(auto i = 0; i < signatures.size(); i++){
        int signature_index = signatures.at(i).find('=') + 1;
        string signature_type = signatures.at(i).substr(0,signature_index -1);
        string signature_hex = signatures.at(i).substr(signature_index,signatures.at(i).length() -1);

        
        for(auto j = 0; j < hex.size(); j++){
            if(hex.at(j).find(signature_hex) != string::npos){
                if(fullinfo == false){
                    logs << "\n----------------------------\nFound virums: " + signature_type + "\n" + "In file" + file_names.at(j) + "\n" "File Hex " + hex.at(j).substr(0,59) + "..." + "\n" "Pared with Signature Hex: " + signature_hex + "\n"; 
                }
                else{
                    logs << "\n----------------------------\nFound virums: " + signature_type + "\n" + "In file" + file_names.at(j) + "\n" + "\n" "Pared with Signature Hex: " + signature_hex + "\n"; 
                    logs << "\n----------------------------\nFile hex (LONG): \n";   
                    const int n = 59;
                    for(auto k = 0; k < hex.at(j).length(); ++k){
                        if(k%n == 0 && k != 0){
                            logs << "\n";
                        }
                        logs << hex.at(j)[k];
                    }
                }
                virus_counter += 1;
            }
        }
    }
    logs << "\n----------------------------\n" + to_string(virus_counter) + " Different types of malware found\n";
    logs.close();
    cout <<  GREEN <<"\n[*]" << MAGENTA << " Finished scanning";
    cout <<  GREEN <<"\n[*]" << MAGENTA << " Found " << virus_counter << " total malware" << endl;
}
   
//Takes a suspected file as a string and returns its hexdata
string check_file(string &sus_file){
    
    ifstream infile(sus_file, ios_base::binary);
    unsigned char x;
    infile >> noskipws; //Flag for considering initial whitespace characters as valid content
    string hex_data;
    ostringstream oss;
    while(infile >> x){
        long constant = 0x0000000168;
        oss << hex << setw(2) << setfill('0') << int(x);
    }
    hex_data = oss.str();
    return hex_data;
}
//Takes in a  empty signature_container and a path to signatures, and returns a container filled with signatures
vector<string> find_signatures(vector<string> &signature_container, string path_signatures){
    string line;
    
    ifstream signatures;
    signatures.open(path_signatures);

    if(signatures.is_open()){
        while(getline(signatures,line)){
            signature_container.push_back(line);
        }
        
    }
    else{
        cout << GREEN << "\n-------------ERROR------------\n";
        cout << RED << "\n*** Could not find the signatures or its empty...***" << endl;
    }
    signatures.close();

    return signature_container;
}

//Creates a txt file and adds the directory to block
void block(string blockdirectory){
    ofstream blocked;
    blocked.open("blocked.txt", ios::out | ios::app);
    if(blocked.is_open()){
        blocked << blockdirectory + "\n";
        
    }
    blocked.close();
    return;
}
//Clears the block text-file
void clearblock(){
    ofstream clear;
    clear.open("blocked.txt", ios::out | ios::trunc);
    clear.close();
}

//Main
int main(int argc,char** argv){
    cout <<  GREEN << R"(      .o.       oooooo     oooo 
     .888.       `888.     .8'  
    .8"888.       `888.   .8'   
   .8' `888.       `888. .8'    
  .88ooo8888.       `888.8'     
 .8'     `888.       `888'      
o88o     o8888o       `8'       )" << endl;
    cout <<  GREEN <<"\nMade by Oliver Bölin, oliverbolin97@gmail.com, DV1620\n";
    cout <<  GREEN <<"\n\n[1] " << MAGENTA <<"Welcome \n" << GREEN <<"[2]" << MAGENTA <<" Virus Detection System\n";
    cout <<  GREEN <<"[3]" << MAGENTA <<" Run with -h for command-list\n";
    if(argc < 2){
        cout <<  GREEN <<"\n[*] ERROR\n";
        cout <<  RED <<"\n[*] You probably forgot to input a directory" << endl;
        return 0;
    }
    vector<string> signature_container; //Stores all the signatures from DB
    vector<string> sus_files_container; //Stores all the names of the files
    vector<string> hex_container; //Stores all the hexadecimal hashes of the files
    string path_signatures = "signatures.db";
    string directory = argv[1];
    string blockdirectory;
    bool fullinfo = false;
   

    if (auto dir1 = opendir(argv[1])){
        
    }
    else{
        cout << GREEN << "\n[*] ERROR\n";
        cout << RED << "\n[*] Could not find the directory." << endl;
        return 0;
    }
    if(input_validation(directory) == false || check_blocked(directory) == false){
    
        cout <<  GREEN <<"\n[*] ERROR\n";
        cout <<  RED <<"\n[*] Access to those directories are not allowed" << endl;
        return false;
    }

    if(argc > 7){
        cout <<  GREEN <<"\n[*]ERROR\n";
        cout <<  RED <<"\n[*] Too many arguments" << endl;
        return 0;
    }
    string pathtest;
    int opt;
    while((opt = getopt(argc, argv, "cb:fd:h")) != -1){
        switch(opt){
            case 'f':
                fullinfo = true;
                cout <<  YELLOW <<"[->f]Running with fullhex-mode" << endl;
                break;
            case 'd':
                pathtest = optarg;
                if(input_validation(pathtest) == true){
                    path_signatures = argv[optind + 1];
                    cout <<  YELLOW <<"[->d]Running with custom signatures " + path_signatures << endl;
                }
                break;
            case 'h':
                help();
                cout <<  YELLOW <<"[->h]Help " << endl; 
                break;
            case 'b':
                blockdirectory = optarg;
                block(blockdirectory);
                cout <<  YELLOW <<"[->b]Blocking " + blockdirectory << endl;
                break;
            case 'c':
                clearblock();
                cout <<  YELLOW <<"[->c]Clearing " << endl;
        }
    }
    if(optind >= argc){
        path_signatures = "signatures.db";
    }

    const char *c_directory = directory.c_str();
    find_signatures(signature_container, path_signatures); //To find the signatures from DB
    find_subdirs(c_directory, sus_files_container, directory); //To find the directories and files
    

        
    
    for(auto i = 0; i < sus_files_container.size(); i++){ //Take each file and check their hex
        hex_container.push_back(check_file(sus_files_container.at(i)));
    }


    compare_hex(hex_container, signature_container, sus_files_container, fullinfo);
    return 0;
}
