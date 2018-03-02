#pragma warning (disable:4996 4018)

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>

char const header[3] = { 'P', 'K', 'T' };
uint8_t snifferId = 12;
uint32_t build = 0;
char sessionKey[40];
char lang[4] = { 'e', 'n', 'U', 'S' };
bool pauseAtEnd = false;
char const ver[2] = { 0x1, 0x3 };
char const serverDirection[4] = { 'C', 'M', 'S', 'G' };
char const clientDirection[4] = { 'S', 'M', 'S', 'G' };
uint32_t sessionid = 0;
uint32_t tickCount = 0;
std::string optionalData = "";

typedef std::vector<std::string> StringVector;

// went back to manual split, i have no idea why that regex does not work on my linux machine lul
StringVector Tokenize(std::string& in, std::string format)
{
    char* c = new char[in.size() + 1];
    strcpy(c, in.c_str());
    StringVector out;

    char* sub = strtok(c, format.c_str());
    while (sub != NULL)
    {
        out.push_back(sub);
        sub = strtok(NULL, format.c_str());
    }

    delete[] c;

    return out;
}

struct MillisecondsData
{
    uint8_t bytes0;
    int16_t bytes1;
    int64_t bytes2;
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

        std::smatch matches;
        if (std::regex_search(filename, matches, std::regex("_[0-9]+_")))
        {
            build = std::stoi(std::string(matches[0]).substr(1, 5));
            std::cout << "found build in filename - setting it to " << build << std::endl;
        }

        uint32_t counter = 0;
        std::string buf;
        while (std::getline(in, buf))
        {
            printf("\r%u               ", ++counter);

            StringVector token = Tokenize(buf, " ;:\r\n");
            std::string time = token[1];
            std::string direction = token[3];
            std::string opcode = token[5];
            std::string data = token.size() < 8 ? "" : token[7];

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

    void InitDump(uint64_t _startTime)
    {
        headerInit = true;
        memset(sessionKey, 0, sizeof(sessionKey));

        out.write(header, sizeof(header));
        out.write(ver, sizeof(ver));
        out.write((char const*)&snifferId, sizeof(snifferId));
        out.write((char const*)&build, sizeof(build));
        out.write((char const*)&lang, sizeof(lang));
        out.write((char const*)&sessionKey, sizeof(sessionKey));

        uint32_t startTime = msData ? uint32_t(_startTime / 1000) : uint32_t(_startTime);
        out.write((char const*)&startTime, sizeof(startTime));    // timestamp

        out.write((char const*)&tickCount, sizeof(tickCount));      // tick count

        if (msData)
        {
            uint32_t msDataLen = sizeof(msData->bytes0) + sizeof(msData->bytes1) + sizeof(msData->bytes2);
            out.write((char const*)&msDataLen, sizeof(msDataLen));
            out.write((char const*)&msData->bytes0, sizeof(msData->bytes0));
            out.write((char const*)&msData->bytes1, sizeof(msData->bytes1));
            out.write((char const*)&msData->bytes2, sizeof(msData->bytes2));
        }
        else
        {
            uint32_t optionalDataLen = optionalData.length();
            char* cp = new char[optionalDataLen];
            memcpy(cp, optionalData.c_str(), optionalDataLen);
            out.write((char const*)&optionalDataLen, sizeof(optionalDataLen));
            out.write(cp, optionalDataLen);
            delete[] cp;
        }
    }

    void DumpOpcode(uint32_t op, bool cmsg, std::string data, uint64_t time, uint32_t counter)
    {
        if (cmsg)
            out.write(serverDirection, sizeof(serverDirection));
        else
            out.write(clientDirection, sizeof(clientDirection));

        out.write((char const*)&sessionid, sizeof(sessionid));

        if (firstPacketTime == 0)
            firstPacketTime = time;

        uint32_t packetTime = tickCount + ((msData ? 1 : 1000) * uint32_t(time - firstPacketTime));
        out.write((char const*)&packetTime, sizeof(packetTime));

        uint32_t optdatalen = 0;
        out.write((char const*)&optdatalen, sizeof(optdatalen));
        uint32_t datalen = data.length() / 2 + 4;
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
    uint64_t firstPacketTime;
    MillisecondsData* msData;
};

void readConfigFile(std::string const& iniPath)
{
    std::ifstream inputConfig;
    inputConfig.open(iniPath);

    std::string buf;
    size_t pos;
    while (!inputConfig.eof())
    {
        inputConfig >> buf;

        if (!build)
        {
            pos = buf.find("Build");
            if (pos != buf.npos)
                build = std::stoi(buf.substr(pos + 6));
        }

        pos = buf.find("Locale");
        if (pos != buf.npos)
            memcpy(lang, buf.substr(pos + 7, 4).c_str(), 4);
        pos = buf.find("PauseAtEnd");
        if (pos != buf.npos)
            pauseAtEnd = std::stoi(buf.substr(pos + 11)) > 0;
    }
}

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
    readConfigFile(iniPath);

    std::cout << "Client build assumed: '" << lang << "' " << build << std::endl;

    for (auto i = 1; i < argc; ++i)
    {
        try
        {
            snifferId = 12; // Reset sniffer version because we change it if the time in the file is in milliseconds
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
