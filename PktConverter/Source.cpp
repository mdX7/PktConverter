#pragma warning (disable:4996 4018)

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <Windows.h>

char const header[3] = { 'P', 'K', 'T' };
std::uint8_t snifferId = 12;
std::uint32_t build = 16357;
char sessionKey[40];
char lang[4] = { 'e', 'n', 'U', 'S' };
char const ver[2] = { 0x1, 0x3 };
char const serverDirection[4] = { 'C', 'M', 'S', 'G' };
char const clientDirection[4] = { 'S', 'M', 'S', 'G' };
std::uint32_t sessionid = 0;
std::uint32_t tickCount = 0;
std::string optionalData = "";

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

struct MillisecondsData
{
    std::uint8_t bytes0;
    std::int16_t bytes1;
    std::int64_t bytes2;
};

class Converter
{
    public:
        Converter(std::string _filename) : filename(_filename)
        {
            headerInit = false;
            in.open(_filename.c_str(), std::ios::in);
            out.open((_filename + ".pkt").c_str(), std::ios::out | std::ios::binary);
            firstPacketTime = 0;
            msData = nullptr;
        }

        ~Converter()
        {
            in.close();
            out.close();
            delete msData;
        }

        void Convert(int pos = 1, int total = 1)
        {
            std::cout << "[" << pos << "/" << total << "]" << " Converting " << filename << "..." << std::endl;

            std::uint32_t counter = 0;
            std::string buf;
            while (std::getline(in, buf))
            {
                printf("\r%u               ", ++counter);

                StringVector m = get_matches(buf, "^Time: ([0-9]+,?[0-9]+?);OpcodeType: (ClientMessage|ServerMessage);OpcodeValue: ([0-9]+);Packet: ([0-9A-Z]*);$");
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

                if (time.length() > 10)
                {
                    time = time.substr(0, time.find(','));
                    if (!msData)
                    {
                        snifferId = 83;
                        msData = new MillisecondsData();
                        msData->bytes0 = 0xFF;
                        msData->bytes1 = 0x0107;
                        msData->bytes2 = atoll(time.c_str()) * 10000 + 116444736000000000;
                    }
                }

                std::uint32_t op = atoi(opcode.c_str());
                std::uint64_t _time = atoll(time.c_str());

                if (!headerInit)
                    InitDump(_time);

                DumpOpcode(atoi(opcode.c_str()), strcmp(direction.c_str(), "ClientMessage") == 0, data, _time, counter);
            }

            std::cout << std::endl << "Done!.." << std::endl << std::endl;
        }

        void InitDump(std::uint64_t _startTime)
        {
            headerInit = true;
            memset(sessionKey, 0, sizeof(sessionKey));

            out.write(header, sizeof(header));
            out.write(ver, sizeof(ver));
            out.write((char const*)&snifferId, sizeof(snifferId));
            out.write((char const*)&build, sizeof(build));
            out.write((char const*)&lang, sizeof(lang));
            out.write((char const*)&sessionKey, sizeof(sessionKey));

            std::uint32_t startTime = msData ? std::uint32_t(_startTime / 1000) : std::uint32_t(_startTime);
            out.write((char const*)&startTime, sizeof(startTime));    // timestamp

            out.write((char const*)&tickCount, sizeof(tickCount));      // tick count

            if (msData)
            {
                std::uint32_t msDataLen = sizeof(msData->bytes0) + sizeof(msData->bytes1) + sizeof(msData->bytes2);
                out.write((char const*)&msDataLen, sizeof(msDataLen));
                out.write((char const*)&msData->bytes0, sizeof(msData->bytes0));
                out.write((char const*)&msData->bytes1, sizeof(msData->bytes1));
                out.write((char const*)&msData->bytes2, sizeof(msData->bytes2));
            }
            else
            {
                std::uint32_t optionalDataLen = optionalData.length();
                char* cp = new char[optionalDataLen];
                memcpy(cp, optionalData.c_str(), optionalDataLen);
                out.write((char const*)&optionalDataLen, sizeof(optionalDataLen));
                out.write(cp, optionalDataLen);
                delete[] cp;
            }
        }

        void DumpOpcode(std::uint32_t op, bool cmsg, std::string data, std::uint64_t time, std::uint32_t counter)
        {
            if (cmsg)
                out.write(serverDirection, sizeof(serverDirection));
            else
                out.write(clientDirection, sizeof(clientDirection));

            out.write((char const*)&sessionid, sizeof(sessionid));

            if (firstPacketTime == 0)
                firstPacketTime = time;

            std::uint32_t packetTime = tickCount + ((msData ? 1 : 1000) * std::uint32_t(time - firstPacketTime));
            out.write((char const*)&packetTime, sizeof(packetTime));

            std::uint32_t optdatalen = 0;
            out.write((char const*)&optdatalen, sizeof(optdatalen));
            std::uint32_t datalen = data.length() / 2 + 4;
            out.write((char const*)&datalen, sizeof(datalen));

            out.write((char const*)&op, sizeof(op));

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

                out.write((char const*)&val, sizeof(val));
            }
        }

    private:
        bool headerInit;
        std::string filename;
        std::ofstream out;
        std::ifstream in;
        std::uint64_t firstPacketTime;
        MillisecondsData* msData;
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
