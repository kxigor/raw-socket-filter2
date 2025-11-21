#ifndef TRACE_DECEPTOR_H
#define TRACE_DECEPTOR_H

#include <arpa/inet.h>
#include <linux/version.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "include/raw_socket_forwarder/raw_socket_forwarder.h"

#define TRIGGER_IP "66.66.66.66"
#define FAKE_NET_PREFIX "11.22.33."
#define MAX_HOPS 30

static const char* trauma_lyrics[] = {"Years.kept.passing.by",
                                      "Still.my.mind.hasn-t.forgotten",
                                      "Corpses.lying.among.debris",
                                      "Unrecognizable.rotten",
                                      "Suffering.from.a.trauma",
                                      "It.keeps.haunting.me",
                                      "Considering.me.an.obsessional",
                                      "But.they.will.never.know",
                                      "The.massacres.in.former.days",
                                      "Hatred.won-t.let.go",
                                      "Nightmares.controlling.my.life",
                                      "In.my.own.world.I.live",
                                      "Suffer.day.and.night",
                                      "I.face.pain.I.don-t.want.to.see",
                                      "Makes.me.realize",
                                      "It.won-t.leave.me",
                                      "Horrible.events.pass.me.by",
                                      "I.wake.from.my.cry",
                                      "In.the.middle.of.the.night",
                                      "I.find.myself.shuddering.in.sweat",
                                      "Memories.of.sorrow.and.death",
                                      "Nightmares.controlling.my.life",
                                      "Trauma",
                                      "Horrible.events.pass.me.by",
                                      "Trauma",
                                      "Bodies.filled.with.lead",
                                      "They.all.have.met.an.untimely.death",
                                      "Blood.was.everywhere",
                                      "They.lived.in.chaos.and.despair",
                                      "I.suffer.day.and.night",
                                      "Trauma",
                                      "I.wake.from.my.cries",
                                      "Trauma",
                                      "Considering.me.an.obsessional",
                                      "But.they.will.never.know",
                                      "The.massacres.in.former.days",
                                      "Hatred.won-t.let.go"};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define UDP_SOURCE(udp) ((udp)->uh_sport)
#define UDP_DEST(udp) ((udp)->uh_dport)
#define UDP_LEN(udp) ((udp)->uh_ulen)
#define UDP_CHECK(udp) ((udp)->uh_sum)
#else
#define UDP_SOURCE(udp) ((udp)->source)
#define UDP_DEST(udp) ((udp)->dest)
#define UDP_LEN(udp) ((udp)->len)
#define UDP_CHECK(udp) ((udp)->check)
#endif

Packet traceroute_answer(const Packet input, void* data);
filter_status_e traceroute_filter(const Packet input, void* data);
void traceroute_cleanup(Packet user_packet, void* data);

#endif  // TRACE_DECEPTOR_H