#include <stdio.h>
#include <pcap.h>

#define LINE_LEN 16

int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
    char* filename = (char*)malloc(1024 * sizeof(char));

    long long firstPCRs[8192]; //The PCR of the first packet with a PCR for each PID
    long long firstPCRsmsec[8192]; //The time when the first packet with a PCR has arrived for each PID
    long long lastPCRs[8192]; //The PCR of the last packet with a PCR for each PID
    long long lastPCRsmsec[8192]; //The time when the last packet with a PCR has arrived for each PID
    //-1 : PID doesn't exist
    //-2 : PID exists but no PCR was captured(or only one PCR captured, if -2 is in lastPCRs)
    for (int i = 0; i < 8192; i++) firstPCRs[i] = -1;
    for (int i = 0; i < 8192; i++) firstPCRsmsec[i] = -1;
    for (int i = 0; i < 8192; i++) lastPCRs[i] = -1;
    for (int i = 0; i < 8192; i++) lastPCRsmsec[i] = -1;

    if (argc != 2)
	{
		printf("Please write the full path of the PCAP file:\n");
		gets(filename);
	}
	else filename = argv[1];

	/* Open the capture file */
	if ((fp = pcap_open_offline(filename,			// name of the device
						 errbuf					// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", argv[1]);
		scanf("%s", filename);
		return -1;
	}
	/* Retrieve the packets from the file */
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) //go over all packets
	{
		int cur = 12; //skip MAC Adreeses
		int len = header->caplen;
		long long time = ((long long)header->ts.tv_sec) * 1000000 + (long long)header->ts.tv_usec;
		if (len > 14 && pkt_data[cur] == 0x08 && pkt_data[cur + 1] == 0x00 && ((pkt_data[cur + 2] & 0xf0) == 0x40)) //If IP Packet
		{
		    cur += 2; //skip MAC Header
		    if (len > (cur+9) && pkt_data[cur+9] == 0x11) //If UDP Protocol
		    {
                if ((pkt_data[cur] & 0x0f) > 0x05) cur += 4; //skip IP OPTIONS
                cur += 20; //skip IP HEADER
                cur += 8; //skip UDP HEADER
                for (int cur188 = cur; len > cur188; cur188 += 188)
                {
                    cur = cur188;
                    if (len > cur + 2 && pkt_data[cur] == 0x47) //Validate sync byte
                    {
                        int pid = ((pkt_data[cur + 1] & 0x1f) << 8) + pkt_data[cur + 2];
                        if ((pkt_data[cur + 1] & 0x80) != 0x80 && pid >= 0 && pid < 8192) //No corruption
                        {
                            if (firstPCRs[pid] == -1) //This is the first
                            {
                                firstPCRs[pid] = -2; //This pid exists
                                firstPCRsmsec[pid] = -2; //This pid exists
                                lastPCRs[pid] = -2; //This pid exists
                                lastPCRsmsec[pid] = -2; //This pid exists
                            }
                            if ((len > cur + 3) && ((pkt_data[cur + 3] & 0x20) == 0x20)) //Adaptation field exists
                            {
                                cur += 4; //skip to the adaptation field
                                if (len > cur + 7 && (pkt_data[cur + 1] & 0x10) == 0x10) //PCR exists
                                {
                                    cur += 2; //skip to the pcr
                                    long long origPCR = 0; //Original PCR
                                    for (int c = 0; c < 6; c++) //Six bytes - BigEndian
                                    {
                                        origPCR <<= 8;
                                        origPCR += pkt_data[cur + c];
                                    }
                                    long long PCR339 = ((origPCR & 0xffffffff8000) >> 15) * 300 + (origPCR & 0x1ff); //First 33 bits + last 9 bits
                                    long long PCR = PCR339 / 27;
                                    if (firstPCRs[pid] == -2) //This is the first
                                    {
                                        firstPCRs[pid] = PCR;
                                        firstPCRsmsec[pid] = time;
                                    }
                                    else
                                    {
                                        lastPCRs[pid] = PCR;
                                        lastPCRsmsec[pid] = time;
                                    }
                                } //PCR exists
                            } //Adaptation field exists
                        } //No corruption
                    } //Validate sync byte
                } //for
		    } //If UDP Protocol
		} //If IP Packet
		//printf("\n\n");
	} //go over all packets

	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}

	pcap_close(fp);


	//Print results
	for (int i = 0; i < 8192; i++)
	    if (firstPCRs[i] != -1)
	        if (firstPCRs[i] != -2)
                if (lastPCRs[i] != -2)
                {
                    printf("PID Hex: %4x\n", i);
                    printf("PCR Drift (deca-kilo-percent): %20lld\n", (1000000 * ((lastPCRsmsec[i] - firstPCRsmsec[i]) - (lastPCRs[i] - firstPCRs[i]))) / (lastPCRs[i] - firstPCRs[i]));
                    printf("\n");
                }
    scanf("%s", filename);
	return 0;
}
