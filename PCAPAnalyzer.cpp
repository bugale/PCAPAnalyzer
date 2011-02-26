#include <stdio.h>
#include <pcap.h>
#include <time.h>
#define WIN32_LEAN_AND_MEAN
 
long long gettimeofday()
{
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	return (((ft.dwHighDateTime << 32) | ft.dwLowDateTime) - 11644473600000000) / 10000;
}

int main(int argc, char **argv)
{
	SetConsoleTitle("PCAP Analyzer");

    char filename[1024];
    if (argc != 2)
	{
		printf("Please write the full path of a PCAP file, or a path relative to this program:\n");
		gets(filename);
	}

	long long time_start = 0;
	long long time_arrays = 0;
	long long time_read = 0;
	long long time_end = 0;

	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;

	int packets = 0;
	int ippackets = 0;
	int udppackets = 0;
	int tspackets = 0;
	int transportstreams = 0;
	int pcrpackets = 0;
	int udpports = 0;
	int pids = 0;
	int pcrpids = 0;
	
	time_start = gettimeofday();
	long long* lastUDPsmsec   = (long long*)malloc(65536 * sizeof(long long)); //The time when the last packet with had arrived for each UDP Port
	long long* jitterUDPsmsec = (long long*)malloc(65536 * sizeof(long long)); //The current jitter for each UDP Port
    long long* firstPCRs      = (long long*)malloc(8192  * sizeof(long long)); //The PCR of the first packet with a PCR for each PID
    long long* firstPCRsmsec  = (long long*)malloc(8192  * sizeof(long long)); //The time when the first packet with a PCR had arrived for each PID
    long long* lastPCRs       = (long long*)malloc(8192  * sizeof(long long)); //The PCR of the last packet with a PCR for each PID
    long long* lastPCRsmsec   = (long long*)malloc(8192  * sizeof(long long)); //The time when the last packet with a PCR had arrived for each PID
	long long* bitssent       = (long long*)malloc(8192  * sizeof(long long)); //The bits which were sent for each PID
	long long* firstmsec      = (long long*)malloc(8192  * sizeof(long long)); //The time when first packet had arrived for each PID
	long long* lastmsec       = (long long*)malloc(8192  * sizeof(long long)); //The time when last packet had arrived for each PID
    for (int i = 0; i < 8192; i++) firstPCRs[i] = -1;
    for (int i = 0; i < 8192; i++) firstPCRsmsec[i] = -1;
    for (int i = 0; i < 8192; i++) lastPCRs[i] = -1;
    for (int i = 0; i < 8192; i++) lastPCRsmsec[i] = -1;
	for (int i = 0; i < 65536; i++) lastUDPsmsec[i] = -1;
	for (int i = 0; i < 65536; i++) jitterUDPsmsec[i] = -1;
	for (int i = 0; i < 8192; i++) bitssent[i] = -1;
	for (int i = 0; i < 8192; i++) firstmsec[i] = -1;
	for (int i = 0; i < 8192; i++) lastmsec[i] = -1;
	time_arrays = gettimeofday();

	printf("\nAnalyzing... This may take some minutes. Please be patient.");
	
	/* Open the capture file */
	if ((fp = pcap_open_offline((argc != 2 ? filename : argv[1]),			// name of the file
						 errbuf					// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\n\nUnable to open the file %s!\n", argv[1]);
		scanf("%s", filename);
		return -1;
	}
	
	/* Retrieve the packets from the file */
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) //go over all packets
	{
		packets++;
		int cur = 12; //skip MAC Adreeses
		int len = header->caplen;
		long long time = ((long long)header->ts.tv_sec) * 1000000 + (long long)header->ts.tv_usec;
		if (len > 14 && pkt_data[cur] == 0x08 && pkt_data[cur + 1] == 0x00 && ((pkt_data[cur + 2] & 0xf0) == 0x40)) //If IP Packet
		{
			ippackets++;
		    cur += 2; //skip MAC Header
		    if (len > (cur + 9) && pkt_data[cur + 9] == 0x11) //If UDP Protocol
		    {
                if ((pkt_data[cur] & 0x0f) > 0x05) cur += 4; //skip IP OPTIONS
                cur += 20; //skip IP HEADER

				udppackets++;
				int destUDPport = (pkt_data[cur + 2] << 8) | pkt_data[cur + 3];
				if (lastUDPsmsec[destUDPport] == -1) udpports++;
				if (lastUDPsmsec[destUDPport] == -1) lastUDPsmsec[destUDPport] = time;
				else
				{
					if (time - lastUDPsmsec[destUDPport] > jitterUDPsmsec[destUDPport]) jitterUDPsmsec[destUDPport] = time - lastUDPsmsec[destUDPport];
					lastUDPsmsec[destUDPport] = time;
				}

                cur += 8; //skip UDP HEADER

				int rounds = 0;
                for (int cur188 = cur; len > cur188; cur188 += 188)
                {
                    cur = cur188;
                    if (len > cur + 2 && pkt_data[cur] == 0x47) //Validate sync byte
                    {
						tspackets++;
						rounds++;

                        int pid = ((pkt_data[cur + 1] & 0x1f) << 8) | pkt_data[cur + 2];
						bitssent[pid] += 1504;
						if (firstmsec[pid] == -1) pids++;
						if (firstmsec[pid] == -1) firstmsec[pid] = time;
						else lastmsec[pid] = time;

                        if ((pkt_data[cur + 1] & 0x80) != 0x80 && pid >= 0 && pid < 8192) //No corruption
                        {
                            if ((len > cur + 3) && ((pkt_data[cur + 3] & 0x20) == 0x20)) //Adaptation field exists
                            {
                                cur += 4; //skip to the adaptation field
                                if (len > cur + 7 && (pkt_data[cur + 1] & 0x10) == 0x10) //PCR exists
                                {
									pcrpackets++;
                                    cur += 2; //skip to the pcr
									long long PCR33 = (((((((pkt_data[cur] << 8) | pkt_data[cur + 1]) << 8) | pkt_data[cur + 2]) << 8) | pkt_data[cur + 3]) << 1) | (pkt_data[cur + 4] >> 7); //First 33 bits
									long long PCR9 = ((pkt_data[cur + 4] & 0x01) << 8) | pkt_data[cur + 5]; //last 9 bits
                                    long long PCR = ((PCR33 * 300) + PCR9) / 27;
                                    if (firstPCRs[pid] == -1) //This is the first
                                    {
										pcrpids++;
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
				if (rounds != 0) transportstreams++;
		    } //If UDP Protocol
		} //If IP Packet
	} //go over all packets
	time_read = gettimeofday();

	if (res == -1)
	{
		printf("\n\nError reading the packets: %s!\n", pcap_geterr(fp));
		scanf("%s", filename);
		pcap_close(fp);
	}
	else
	{
		printf("\n\n\nAnalyzing complete!");
		FILE * pFile;

		pFile = fopen ("PCR-Offset.txt","w");
		fprintf(pFile, "PCR Offset:\n");
		fprintf(pFile, "(Formula: 1000000*(deltaPCR - deltaTime)/deltaPCR)\n");
		fprintf(pFile, "(Note: positive offset will be displayed when the packet came too fast)\n\n");
		for (int i = 0; i < 8192; i++)
			if (firstPCRs[i] != -1 && lastPCRs[i] != -1)
			{
				double offset = (double)1000000 * (((double)lastPCRs[i] - (double)firstPCRs[i]) - ((double)lastPCRsmsec[i] - (double)firstPCRsmsec[i])) / ((double)lastPCRs[i] - (double)firstPCRs[i]);
				fprintf(pFile, "PID Hex: %4x\n", i);
				fprintf(pFile, "PCR Offset: %15.3f ppm\n", offset);
				fprintf(pFile, "\n");
			}
		fclose (pFile);

		pFile = fopen ("PID-Bitrate.txt","w");
		fprintf(pFile, "PID Bitrate:\n");
		fprintf(pFile, "(Note: b = bit, k = 1000, M = 1000000, G = 1000000000)\n\n");
		for (int i = 0; i < 8192; i++)
			if (firstmsec[i] != -1 && lastmsec[i] != -1)
			{
				double bitrate = (double)1000000 * ((double)bitssent[i]) / ((double)lastmsec[i] - (double)firstmsec[i]);
				fprintf(pFile, "PID Hex: %4x\n", i);
				if      (bitrate > (double)1000000000)
					fprintf(pFile, "Bitrate: %15.3f Gbps\n", bitrate / (double)1000000000);
				else if (bitrate > (double)   1000000)
					fprintf(pFile, "Bitrate: %15.3f Mbps\n", bitrate / (double)   1000000);
				else if (bitrate > (double)      1000)
					fprintf(pFile, "Bitrate: %15.3f kbps\n", bitrate / (double)      1000);
				else
					fprintf(pFile, "Bitrate: %15.3f  bps\n", bitrate);
				fprintf(pFile, "\n");
			}
		fclose (pFile);

		pFile = fopen ("UDP-Jitter.txt","w");
		fprintf(pFile, "UDP Jitter:\n\n");
		for (int i = 0; i < 65536; i++)
			if (jitterUDPsmsec[i] != -1)
			{
				double jitter = (double)jitterUDPsmsec[i];
				fprintf(pFile, "Port Dec: %4d\n", i);
				if      (jitter > (double)3600000000)
					fprintf(pFile, "UDP Jitter: %15.3f hours       \n", jitter / (double)3600000000);
				else if (jitter > (double)  60000000)
					fprintf(pFile, "UDP Jitter: %15.3f minutes     \n", jitter / (double)  60000000);
				else if (jitter > (double)   1000000)
					fprintf(pFile, "UDP Jitter: %15.3f seconds     \n", jitter / (double)   1000000);
				else if (jitter > (double)      1000)
					fprintf(pFile, "UDP Jitter: %15.3f miliseconds \n", jitter / (double)      1000);
				else
					fprintf(pFile, "UDP Jitter: %15.3f microseconds\n", jitter);
				fprintf(pFile, "\n");
			}
		fclose (pFile);

		pFile = fopen ("Statistics.txt","w");
		fprintf(pFile, "Ethernet packets processed:               %9d\n", packets);
		fprintf(pFile, "IPv4 packets processed:                   %9d\n", ippackets);
		fprintf(pFile, "packets with a Transport Stream processed:%9d\n", transportstreams);
		fprintf(pFile, "\n");
		fprintf(pFile, "Transport Stream packets processed:       %9d\n", tspackets);
		fprintf(pFile, "packets with PCR processed:               %9d\n", pcrpackets);
		fprintf(pFile, "\n");
		fprintf(pFile, "Number of PIDs processed:                 %9d\n", pids);
		fprintf(pFile, "Number of PIDs with PCR processed:        %9d\n", pcrpids);
		fprintf(pFile, "Number of UDP ports processed:            %9d\n", udpports);
		fclose (pFile);
		
		time_end = gettimeofday();

		printf("\nThe data has been successfuly saved to these files:\n\n");
		printf("  PCR-Offset.txt\n");
		printf("  PID-Bitrate.txt\n");
		printf("  UDP-Jitter.txt\n");
		printf("  Statistics.txt\n");
		printf("\nYou will find these files in the same folder as this program.\n\n\n");
		printf("Arrays creation time: %d miliseconds\n", time_arrays - time_start);
		printf("Packets reading time: %d miliseconds\n", time_read - time_arrays);
		printf("File saving time:     %d miliseconds\n", time_end - time_read);
		printf("Total running time:   %d miliseconds\n", time_end - time_start);
		printf("\n\nYou may close this window now.\n");
		scanf("%s", filename);
		pcap_close(fp);
	}
	return 0;
}
