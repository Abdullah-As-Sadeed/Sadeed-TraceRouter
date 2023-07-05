/* By Abdullah As-Sadeed */

/*
gcc ./Sadeed_TraceRouter.cpp -o ./Sadeed_TraceRouter
*/

#include "arpa/inet.h"
#include "csignal"
#include "iostream"
#include "netdb.h"
#include "netinet/ip.h"
#include "netinet/ip_icmp.h"
#include "stdio.h"
#include "string.h"
#include "sys/time.h"
#include "unistd.h"

#define TERMINAL_TITLE_START "\033]0;"
#define TERMINAL_TITLE_END "\007"

#define TERMINAL_BOLD_START "\033[1m"
#define TERMINAL_BOLD_END "\033[0m"

#define TERMINAL_ANSI_COLOR_RED "\x1b[31m"
#define TERMINAL_ANSI_COLOR_GREEN "\x1b[32m"
#define TERMINAL_ANSI_COLOR_YELLOW "\x1b[33m"
#define TERMINAL_ANSI_COLOR_RESET "\x1b[0m"

#define MAXIMUM_HOPS 30
#define PACKET_SIZE 64

unsigned short Calculate_Checksum(unsigned short *buffer, int length)
{
    unsigned int summation = 0;
    unsigned short *temporary = buffer;
    unsigned short result;

    for (; length > 1; length -= 2)
    {
        summation += *temporary++;
    }

    if (length == 1)
    {
        summation += *(unsigned char *)temporary;
    }

    summation = (summation >> 16) + (summation & 0xFFFF);
    summation += (summation >> 16);
    result = ~summation;

    return result;
}

void Trace_Route(const char *target)
{
    printf(TERMINAL_TITLE_START "Sadeed Port Scanner: tracing route to %s" TERMINAL_TITLE_END, target);

    int ttl = 1;
    int sockfd;
    int data_length = sizeof(struct icmphdr);
    struct sockaddr_in destination_address;
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    char packet[PACKET_SIZE];
    char buffer[PACKET_SIZE];
    struct timeval timeout = {1, 0}; /* 1s timeout for receiving packets */
    fd_set read_set;

    struct hostent *host = gethostbyname(target);
    if (host == NULL)
    {
        printf(TERMINAL_ANSI_COLOR_RED "Unable to resolve target: %s\n" TERMINAL_ANSI_COLOR_RESET, target);
        return;
    }

    memset(&destination_address, 0, sizeof(destination_address));
    destination_address.sin_family = AF_INET;
    destination_address.sin_addr = *((struct in_addr *)host->h_addr);

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
    {
        perror(TERMINAL_ANSI_COLOR_RED "socket" TERMINAL_ANSI_COLOR_RESET);
        return;
    }

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    printf(TERMINAL_BOLD_START "%-5s %-20s %-40s %s\n" TERMINAL_BOLD_END, "Hop", "IP Address", "Hostname", "Time (ms)");

    while (ttl <= MAXIMUM_HOPS)
    {
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
        {
            perror(TERMINAL_ANSI_COLOR_RED "setsockopt" TERMINAL_ANSI_COLOR_RESET);
            return;
        }

        memset(packet, 0, PACKET_SIZE);
        icmp_header = (struct icmphdr *)packet;
        icmp_header->type = ICMP_ECHO;
        icmp_header->code = 0;
        icmp_header->un.echo.id = getpid();
        icmp_header->un.echo.sequence = ttl;
        icmp_header->checksum = 0;
        icmp_header->checksum = Calculate_Checksum((unsigned short *)icmp_header, data_length);

        if (sendto(sockfd, packet, data_length, 0, (struct sockaddr *)&destination_address, sizeof(destination_address)) <= 0)
        {
            perror(TERMINAL_ANSI_COLOR_RED "sendto" TERMINAL_ANSI_COLOR_RESET);
            return;
        }

        int bytes_received = 0;
        while (1)
        {
            FD_ZERO(&read_set);
            FD_SET(sockfd, &read_set);

            int ready = select(sockfd + 1, &read_set, NULL, NULL, &timeout);
            if (ready < 0)
            {
                perror(TERMINAL_ANSI_COLOR_RED "select" TERMINAL_ANSI_COLOR_RESET);
                return;
            }

            if (ready == 0)
            {
                printf("%-5d %-20s %-40s %s\n", ttl, "*", "-", "-"); /* Timeout reached, no reply received */
                break;
            }

            if (FD_ISSET(sockfd, &read_set))
            {
                bytes_received = recv(sockfd, buffer, PACKET_SIZE, 0);
                break;
            }
        }

        if (bytes_received > 0)
        {
            ip_header = (struct iphdr *)buffer;
            struct in_addr address;
            address.s_addr = ip_header->saddr;
            printf("%-5d %-20s ", ttl, inet_ntoa(address));

            if (ip_header->saddr == destination_address.sin_addr.s_addr)
            {
                printf(TERMINAL_ANSI_COLOR_GREEN "%-40s " TERMINAL_ANSI_COLOR_RESET, "Reached Destination");
            }
            else
            {
                struct hostent *host = gethostbyaddr(&(ip_header->saddr), sizeof(ip_header->saddr), AF_INET);
                if (host != NULL)
                {
                    printf("%-40s ", host->h_name);
                }
                else
                {
                    printf("%-40s ", "-");
                }
            }

            struct timeval send_time, receive_time;
            gettimeofday(&send_time, NULL);
            long long send_msec = send_time.tv_sec * 1000LL + send_time.tv_usec / 1000;

            usleep(100000); /* Wait for a short time before receiving to get accurate timing */

            gettimeofday(&receive_time, NULL);
            long long receive_milli_second = receive_time.tv_sec * 1000LL + receive_time.tv_usec / 1000;

            printf("%lld\n", receive_milli_second - send_msec);

            if (ip_header->saddr == destination_address.sin_addr.s_addr)
            {
                printf(TERMINAL_TITLE_START "Sadeed Port Scanner: traced route to %s" TERMINAL_TITLE_END, target);
                break;
            }
        }

        ttl++;
    }

    close(sockfd);
}

void Handle_Signal(int signal)
{
    if (signal == SIGINT)
    {
        printf(TERMINAL_ANSI_COLOR_RED "\n\nYou interrupted me by SIGINT signal.\n" TERMINAL_ANSI_COLOR_RESET);
        exit(signal);
    }
}

int main(int argument_count, char *argument_values[])
{
    signal(SIGINT, Handle_Signal);

    printf(TERMINAL_TITLE_START "Sadeed TraceRouter" TERMINAL_TITLE_END);

    if (argument_count != 2)
    {
        printf(TERMINAL_ANSI_COLOR_YELLOW "Usage: %s <IP address or domain>\n" TERMINAL_ANSI_COLOR_RESET, argument_values[0]);
        return 1;
    }

    Trace_Route(argument_values[1]);

    return 0;
}
