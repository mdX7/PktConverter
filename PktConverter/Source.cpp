#pragma warning (disable:4996 4018)

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <Windows.h>

const char header[3] = { 'P', 'K', 'T' };
const unsigned char snifferId = 12;
unsigned int build = 16357;
char sessionKey[40];
char lang[4] = { 'e', 'n', 'U', 'S' };
const char ver[2] = { 0x1, 0x3 };
const char serverDirection[4] = { 'C', 'M', 'S', 'G' };
const char clientDirection[4] = { 'S', 'M', 'S', 'G' };
const unsigned int sessionid = 0;
const std::string copyright = "";

typedef std::vector<std::string> StringVector;
StringVector get_matches(std::string const& in, std::string const& regexpr)
{
    std::regex regex(regexpr);

    std::smatch matches;
    std::regex_match(in, matches, regex);

    std::vector<std::string> out;

    for (auto e : matches)
        out.push_back(e.str());

    return out;
}

class Converter
{
    public:
        Converter(std::string _filename) : filename(_filename)
        {
            headerInit = false;
            in.open(_filename.c_str(), std::ios::in);
            out.open((_filename + ".pkt").c_str(), std::ios::out | std::ios::binary);
        }

        ~Converter()
        {
            in.close();
            out.close();
        }

        void Convert(int pos = 1, int total = 1)
        {
            std::cout << "[" << pos << "/" << total << "]" << " Converting " << filename << "..." << std::endl;

            unsigned int counter = 0;
            std::string buf;
            while (std::getline(in, buf))
            {
                printf("\r%u               ", ++counter);

                StringVector m = get_matches(buf, "^Time: ([0-9]+);OpcodeType: (ClientMessage|ServerMessage);OpcodeValue: ([0-9]+);Packet: ([0-9A-Z]*);$");
                if (!m.size())
                {
                    std::cout << std::endl << "ERROR: wrong format at line " << counter << ". Skipping." << std::endl;
                    continue;
                }

                std::string time = m[1];
                std::string direction = m[2];
                std::string opcode = m[3];
                std::string data = m[4];
                if (data.size() % 2 == 1)
                {
                    std::cout << std::endl << "ERROR: wrong format at line " << counter << ". Skipping." << std::endl;
                    continue;
                }

                unsigned int op = atoi(opcode.c_str());
                unsigned int _time = atoi(time.c_str());

                if (!headerInit)
                    InitDump(_time);

                DumpOpcode(atoi(opcode.c_str()), strcmp(direction.c_str(), "ClientMessage") == 0, data, _time, counter);
            }

            std::cout << std::endl << "Done!.." << std::endl << std::endl;
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

        void DumpOpcode(unsigned int op, bool cmsg, std::string data, unsigned int time, unsigned int counter)
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

            for (auto i = 0; ; i += 2)
            {
                if (i >= data.length())
                    return;

                unsigned char val = 0;
                for (auto j = 0; j < 2; ++j)
                {
                    if (data[i + j] >= 'A' && data[i + j] <= 'F')
                        val += (data[i + j] - 'A' + 10) * (j ? 1 : 16);
                    else if (data[i + j] >= '0' && data[i + j] <= '9')
                        val += (data[i + j] - '0') * (j ? 1 : 16);
                }

                out.write((const char*)&val, sizeof(val));
            }
        }

    private:
        bool headerInit;
        std::string filename;
        std::ofstream out;
        std::ifstream in;
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
    GetPrivateProfileStringA("PKTConverter", "ClientLocale", "enUS", locale, 255, iniPath.c_str());
    memcpy(lang, locale, 4);
    bool pauseAtEnd = GetPrivateProfileIntA("PKTConverter", "PauseAtEnd", 0, iniPath.c_str()) > 0;

    std::cout << "Client build assumed: " << locale << " " << build << std::endl;

    for (auto i = 1; i < argc; ++i)
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

    if (pauseAtEnd)
        system("pause");

    return 0;
}