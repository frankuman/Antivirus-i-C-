//Gjort av Oliver Bölin & Oskar Hansson
//Kurskod 1620
//Startdatum 24/01/2022


//Version 1.2


//Includes
#include <iostream>
#include <string>
#include <fstream> 
#include <vector>
#include <iomanip>
#include <dirent.h> //opendir() 
#include <libgen.h>
using namespace std;

void help(){
    cout << "\n-------------HELP-------------\n";
    cout << "\n->Examplelist<-\n ** ./dv1620program /home/user/Desktop/TestDir ** \nto run a normal run\n\n ** ./dv1620program /home/user/Desktop/TestDir -f **\n to run with full hexes in logs \n\n ** ./dv1620program /home/user/Desktop/TestDir -h /home/user/Desktop/signatures.db **\n to run with other signatures \n\n ** ./dv1620program /home/user/Desktop/TestDir -f -h /home/user/Desktop/signatures.db **\n to run with fullhex-mode and other signatures \n" << endl;
    cout << "->Commandlist<-\n [1] path to directory to start the search \n [2] -f for full hex in logs \n [3] -h to specify a signature database followed up by path" << endl;
}
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
void compare_hex(vector<string>& hex, vector<string>& signatures, vector<string>& file_names, bool& fullinfo){
    ofstream logs("logs.txt");
    int virus_counter = 0;

    for(auto i = 0; i < signatures.size(); i++){
        int signature_index = signatures.at(i).find('=') + 1;
        string signature_type = signatures.at(i).substr(0,signature_index -1);
        string signature_hex = signatures.at(i).substr(signature_index,signatures.at(i).length() -1);
        //cout << signature_hex << endl;
        //cout << signature_type << endl;
        
        for(auto j = 0; j < hex.size(); j++){
            //cout << "\nchecking: " + hex.at(j) + "\nwith: " + signature_hex << endl;
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
   
//Is supposed to create the hexadecimal for the files (?)
string check_file(string &sus_file){
    
    ifstream infile(sus_file, ios_base::binary);
    unsigned char x;
    infile >> noskipws;
    string hex_data;
    ostringstream oss;
    while(infile >> x){
        long constant = 0x0000000168;
        oss << hex << setw(2) << setfill('0') << int(x);
    }
    hex_data = oss.str();
    return hex_data;
}
//Finds the signatures (If they're in the same dictionary as the program) and puts them into a container
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
        help();
        cout << "\n-------------ERROR------------\n";
        cout << "\n*** Could not find the signatures or its empty...***" << endl;
    }
    signatures.close();

    return signature_container;
}


//Main
int main(int argc,char** argv){
    cout << "----------Welcome------------\nVirus Detection System\n";
    cout << "Run with --help for command-list\n";
    
    //string directory = "/home/olive/Desktop/TestDir/SubDir7/SubSubDir75";
    vector<string> signature_container; //Stores all the signatures from DB
    vector<string> sus_files_container; //Stores all the names of the files
    vector<string> hex_container; //Stores all the hexadecimal hashes of the files
    string path_signatures;
    bool fullinfo = false;
    string directory = argv[1];
    string info = "temp";
    string ownpath = "temp";



    if(argv[2] != 0){
        info = argv[2];
    }
    if(argv[3] != 0){
        ownpath = argv[3];
    }
    cout << "Logs found in program folder\n-----------------------------\n";
    if(info == "-f"){
        fullinfo = true;
        cout << "->Running with fullhex-mode" << endl;
        if(ownpath == "-h"){
            path_signatures = argv[4];
            cout << "->Running with custom signatures " + path_signatures << endl;
        }
        else{
            path_signatures = "signatures.db";
        }
    }
    else if(info == "--help" || directory == "--help"){
        help();
    }
    else if(info == "-h"){
        path_signatures = argv[3];
        cout << "Running with custom signatures " + path_signatures << endl;
    }
    else{
        if(argv[3] != "-h"){
            path_signatures = "signatures.db";
            cout << "->Running with normal settings" << endl;
        }
    }
    
  
    const char *c_directory = directory.c_str();
    find_signatures(signature_container, path_signatures); //To find the signatures from DB
    find_subdirs(c_directory, sus_files_container, directory); //To find the directories and files
    

    if(sus_files_container.size() == 0){
        help();
        cout << "\n-------------ERROR------------\n";
        cout << "\n*** Could not find the directory...***" << endl;
      
       
    }

        
    
    for(auto i = 0; i < sus_files_container.size(); i++){ //Take each file and check their hex
        hex_container.push_back(check_file(sus_files_container.at(i))); 
        //cout << "\n-------------------------\n"+hex_container.at(i) << endl;
    }


    compare_hex(hex_container, signature_container, sus_files_container, fullinfo);
    return 0;
}
