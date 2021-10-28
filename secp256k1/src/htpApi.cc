#include "../include/htpApi.h"
using namespace htpLob;


inline int key(std::pair<int,int> x)
{
    return 100*x.first + x.second;
}


void HtpApiThread(std::vector<double>* hashrates, std::vector<std::pair<int,int>>* props)
{
    std::chrono::time_point<std::chrono::system_clock> timeStart;
    timeStart = std::chrono::system_clock::now();
    
    Server svr;

    svr.Get("/", [&](const Request& req, Response& res) {
        
        std::unordered_map<int, double> hrMap;
        for(int i = 0; i < (*hashrates).size() ; i++)
        {
            hrMap[key((*props)[i])] = (*hashrates)[i];
        }
        
        
        
        std::stringstream strBuf;
        strBuf << "{ ";
        
        double totalHr = 0;
        nvmlReturn_t result;
        result = nvmlInit();
        if (result == NVML_SUCCESS)
        { 

            unsigned int devcount;
            result = nvmlDeviceGetCount(&devcount);
            bool first = true;
            strBuf << " \"Gs\":" << devcount << " , ";
            strBuf << " \"Ds\" : [ " ;

            for(int i = 0; i < devcount; i++)
            {
                std::stringstream deviceInfo;
                nvmlDevice_t device;
                result = nvmlDeviceGetHandleByIndex(i, &device);
                if(result == NVML_SUCCESS)
                {
                    
                    nvmlPciInfo_t pciInfo;
                    result = nvmlDeviceGetPciInfo ( device, &pciInfo );
                    if(result != NVML_SUCCESS) { continue; }

                    if(first)
                    {
                        first = false;
                    }
                    else
                    {
                        deviceInfo << " , ";        
                    }

                    deviceInfo << " { ";
                    char devname[256];
                    char UUID[256];
                    result = nvmlDeviceGetName (device, devname, 256 );
                    result = nvmlDeviceGetUUID (device, UUID, 256 );
                    deviceInfo << " \"devname\" : \"" << devname << "\" , ";                    
                    deviceInfo << " \"pciid\" : \"" << pciInfo.busId << "\" , ";
                    deviceInfo << " \"UUID\" : \"" << UUID << "\" , ";

                    double hrate;
                    try{

                        hrate = hrMap.at(key(std::make_pair((int)pciInfo.bus, (int)pciInfo.device)));
                        deviceInfo << " \"h\" : " << hrate << " , ";
                        totalHr += hrate;
                    }
                    catch (...)
                    {}
                    unsigned int temp;
                    unsigned int power;
                    unsigned int fanspeed;
                    result = nvmlDeviceGetFanSpeed ( device, &fanspeed );
                    result = nvmlDeviceGetPowerUsage ( device, &power );
                    result = nvmlDeviceGetTemperature ( device, NVML_TEMPERATURE_GPU, &temp );
                    deviceInfo << " \"FAAn\" : " << fanspeed << " , ";
                    deviceInfo << " \"Powr\" : " << power/1000 << " , ";
                    deviceInfo << " \"teMp\" : " << temp << " }";
                    strBuf << deviceInfo.str();
                }
            }

            strBuf << " ] , \"TtL\": " << totalHr  ;


            result = nvmlShutdown();
        }
        else
        {
            strBuf << " \"error\": \"N V M eL eRR\"";
        }
        std::chrono::time_point<std::chrono::system_clock> timeEnd;
        timeEnd = std::chrono::system_clock::now();
        strBuf << " , \"uptime\": \"" << std::chrono::duration_cast<std::chrono::hours>(timeEnd - timeStart).count() << "h\" ";
        strBuf << " } ";


        std::string str = strBuf.str();
        res.set_content(str.c_str(), "text/plain");
    });
    

    #ifdef HTTPAPI_PORT
    svr.listen("0.0.0.0", HTTPAPI_PORT);
    #else
    svr.listen("0.0.0.0", 36207);
    #endif
}
