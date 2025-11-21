#ifndef TRAUMA_APP_H
#define TRAUMA_APP_H

#include <stddef.h>

static char* trauma_lyrics[] = {"Years.kept.passing.by",
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

static const size_t trauma_lyrics_size =
    sizeof(trauma_lyrics) / sizeof(*trauma_lyrics);

static char* spoofed_ips[] = {"66.66.66.66", "228.228.228.228", "42.42.42.42",
                              "13.37.13.37", "123.123.123.123"};

static const size_t spoofed_ips_size =
    sizeof(spoofed_ips) / sizeof(*spoofed_ips);

#endif  // TRAUMA_APP_H