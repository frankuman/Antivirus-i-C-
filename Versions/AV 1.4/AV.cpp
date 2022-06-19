//Gjort av Oliver Bölin
//Kurskod 1620
//Startdatum 24/01/2022


//Version 1.3


//Includes
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
    cout << "\n-------------HELP-------------\n";
    cout << "[Commandlist]\n[1] path to directory to start the search \n[2] -f for full hex in logs \n[3] -d [DIRECTORY] to specify a signature database followed up by path\n[4] -b [DIRECTORY] to specify a directory that should never be scanned\n[5] -c To clear the blocklist" << endl;
}
//Iterates thru directories and returns a container filled with the paths to files
vector<string> find_subdirs(const char *current_directory, vector<string> &sus_files_container, string directory){
    
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
}
   
//Takes a suspected file as a string and returns its hexdata
string check_file(string &sus_file){
    
    ifstream infile(sus_file, ios_base::binary);
    unsigned char x;
    //infile >> noskipws;
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
        cout << "\n-------------ERROR------------\n";
        cout << "\n*** Could not find the signatures or its empty...***" << endl;
    }
    signatures.close();

    return signature_container;
}
//Checks the input (string) and returns true if the inputs are legal
bool input_validation(string arg1){

    if(arg1 == "/etc/hosts" || arg1 == "/etc/shadow" || arg1 == "/etc/passwd" || arg1 == "/etc/group" || arg1 == "/etc/gshadow" || arg1 == "/etc/pam.d"){
        cout << "\n[*] ERROR\n";
        cout << "\n[*] Access to those directories are not allowed" << endl;
        return false;
    }
    return true;
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
//Checks if directory is in blocked, returns true or false
bool check_blocked(string directory){
    ifstream check;
    string line;
    check.open("blocked.txt");
    if(check.is_open()){
        while(getline(check,line)){
            if(line == directory){
                return false;
            }
        }
    }
    return true;
}
//Main
int main(int argc,char** argv){

    vector<string> signature_container; //Stores all the signatures from DB
    vector<string> sus_files_container; //Stores all the names of the files
    vector<string> hex_container; //Stores all the hexadecimal hashes of the files
    string path_signatures = "signatures.db";
    string directory = argv[1];
    string blockdirectory;
    bool fullinfo = false;

    cout << "\n\n[1] Welcome \n[2] Virus Detection System\n";
    cout << "[3] Run with -h for command-list\n";

    if(argc < 2){
        cout << "\n[*] ERROR\n";
        cout << "\n[*] You probably forgot to input a directory" << endl;
        return 0;
    }

    if(argv[1] == "/etc/hosts" || argv[1] == "/etc/shadow" || argv[1] == "/etc/passwd" || argv[1] == "/etc/group" || argv[1] == "/etc/gshadow" || argv[1] == "/etc/pam.d" || check_blocked(directory) == false){
    
        cout << "\n[*] ERROR\n";
        cout << "\n[*] Access to those directories are not allowed" << endl;
        return false;
    }

    if(argc > 7){
        cout << "\n[*]ERROR\n";
        cout << "\n[*] Too many arguments" << endl;
        return 0;
    }
    string pathtest;
    int opt;
    while((opt = getopt(argc, argv, "cb:fd:h")) != -1){
        switch(opt){
            case 'f':
                fullinfo = true;
                cout << "[->f]Running with fullhex-mode" << endl;
                break;
            case 'd':
                pathtest = optarg;
                if(input_validation(pathtest) == true){
                    path_signatures = argv[optind + 1];
                    cout << "[->d]Running with custom signatures " + path_signatures << endl;
                }
                break;
            case 'h':
                help();
                cout << "[->h]Help " << endl; 
                break;
            case 'b':
                blockdirectory = optarg;
                block(blockdirectory);
                cout << "[->b]Blocking " + blockdirectory << endl;
                break;
            case 'c':
                clearblock();
                cout << "[->c]Clearing " << endl;
        }
    }
    if(optind >= argc){
        path_signatures = "signatures.db";
    }

    const char *c_directory = directory.c_str();
    find_signatures(signature_container, path_signatures); //To find the signatures from DB
    find_subdirs(c_directory, sus_files_container, directory); //To find the directories and files
    

    if(sus_files_container.size() == 0){
  
        cout << "\n[*] ERROR\n";
        cout << "\n[*] Could not find the directory" << endl;
    }

        
    
    for(auto i = 0; i < sus_files_container.size(); i++){ //Take each file and check their hex
        hex_container.push_back(check_file(sus_files_container.at(i)));
    }


    compare_hex(hex_container, signature_container, sus_files_container, fullinfo);
    return 0;
}
