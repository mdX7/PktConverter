#pragma warning (disable:4996 4018)

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <Windows.h>

const char header[3] = { 'P', 'K', 'T' };
const unsigned char snifferId = 12;
unsigned int build = 16357;
char sessionKey[40];
char lang[4] = { 'r', 'u', 'R', 'U' };
const char ver[2] = { 0x1, 0x3 };
const char serverDirection[4] = { 'C', 'M', 'S', 'G' };
const char clientDirection[4] = { 'S', 'M', 'S', 'G' };
const unsigned int sessionid = 0;
const std::string copyright = "Converted by Amaru from Fabian's sniff format to PKT v1.3 standard";

typedef std::vector<std::string> Tokens;
Tokens Tokenize(std::string& in, std::string format)
{
    char* c = new char[in.size() + 1];
    strcpy(c, in.c_str());
    std::vector<std::string> out;

    char* sub = strtok(c, format.c_str());
    while (sub != NULL)
    {
        out.push_back(sub);
        sub = strtok(NULL, format.c_str());
    }

    delete[] c;

    return out;
}

class Converter
{
    public:
        Converter(std::string _filename) : filename(_filename)
        {
            headerInit = false;
            in.open(_filename.c_str(), std::ios::binary);
            out.open((_filename + ".pkt").c_str(), std::ios::out|std::ios::binary);
            checked = false;
        }

        ~Converter()
        {
            in.close();
            out.close();
        }

        void Convert(int pos = 1, int total = 1)
        {
            std::cout << "[" << pos << "/" << total << "]" << " Converting " << filename << "..." << std::endl;
            unsigned int i = 0;

            std::string buf;
            while (std::getline(in, buf))
            {
                if (!checked)
                    CheckFormat(buf);

                printf("\r%u               ", i++);
                Tokens tokens = Tokenize(buf, " ;:\r\n");

                std::string time = tokens[1];
                std::string direction = tokens[3];
                std::string opcode = tokens[5];
                std::string data = tokens.size() < 8 ? "" : tokens[7];
                unsigned int op = atoi(opcode.c_str());
                unsigned int _time = atoi(time.c_str());

                if (!headerInit)
                    InitDump(_time);

                DumpOpcode(atoi(opcode.c_str()), strcmp(direction.c_str(), "CMSG") == 0, data, _time);
            }

            std::cout << std::endl << "Done!.." << std::endl << std::endl;
        }

        void CheckFormat(std::string& line)
        {
            checked = true;
            if (line.find("Time: ") != 0)
                throw std::exception("Invalid input file format!");
        }

        void InitDump(unsigned int _startTime)
        {

            headerInit = true;
            memset(sessionKey, 0, sizeof(sessionKey));
            unsigned int copyrightLen = copyright.length();
            char* cp = new char[copyrightLen];
            memcpy(cp, copyright.c_str(), copyrightLen);

            out.write(header, sizeof(header));
            out.write(ver, sizeof(ver));
            out.write((const char*)&snifferId, sizeof(snifferId));
            out.write((const char*)&build, sizeof(build));
            out.write((const char*)&lang, sizeof(lang));
            out.write((const char*)&sessionKey, sizeof(sessionKey));
            out.write((const char*)&_startTime, sizeof(_startTime));    // timestamp
            out.write((const char*)&_startTime, sizeof(_startTime));    // tick count
            out.write((const char*)&copyrightLen, sizeof(copyrightLen));
            out.write(cp, copyrightLen);

            delete[] cp;
        }

        void DumpOpcode(unsigned int op, bool cmsg, std::string data, unsigned int time)
        {
            if (cmsg)
                out.write(serverDirection, sizeof(serverDirection));
            else
                out.write(clientDirection, sizeof(clientDirection));

            out.write((const char*)&sessionid, sizeof(sessionid));
            out.write((const char*)&time, sizeof(time));

            unsigned int optdatalen = 0;
            out.write((const char*)&optdatalen, sizeof(optdatalen));
            unsigned int datalen = data.length() / 2 + 4;
            out.write((const char*)&datalen, sizeof(datalen));

            out.write((const char*)&op, sizeof(op));

            for (int i = 0; ; i += 2)
            {
                if (i >= data.length())
                    return;

                unsigned char val = 0;
                for (int j = 0; j < 2; ++j)
                {
                    if (data[i+j] >= 'A' && data[i+j] <= 'F')
                        val += (data[i+j] - 'A' + 10) * (j ? 1 : 16);
                    else if (data[i+j] >= '0' && data[i+j] <= '9')
                        val += (data[i+j] - '0') * (j ? 1 : 16);
                    else
                        throw std::exception("Wrong opcode data");
                }

                out.write((const char*)&val, sizeof(val));
            }
        }

    private:
        bool headerInit;
        std::string filename;
        std::ofstream out;
        std::ifstream in;
        bool checked;
};

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: drag and drop files to executable." << std::endl;
        return 1;
    }

    std::string iniPath = argv[0];
    iniPath = iniPath.substr(0, iniPath.find_last_of('\\') + 1);
    iniPath += "PktSettings.ini";
    build = GetPrivateProfileIntA("PKTConverter", "ClientBuild", build, iniPath.c_str());
    char locale[255];
    GetPrivateProfileStringA("PKTConverter", "ClientLocale", "ruRU", locale, 255, iniPath.c_str());
    memcpy(lang, locale, 4);

    std::cout << "Client build assumed: " << locale << " " << build << std::endl;

    for (int i = 1; i < argc; ++i)
    {
        try
        {
            Converter p(argv[i]);
            p.Convert(i, argc - 1);
        }
        catch (std::exception& e)
        {
            std::cout << "Exception occured while parsing " << argv[i] << ":" << std::endl;
            std::cout << e.what() << std::endl << std::endl;
        }
    }

    return 0;
}