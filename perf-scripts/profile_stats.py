# Built and tested with Python 3.8
#
# Collect traces with:
# $ sudo dtrace -n 'profile-997 /pid == $target/ { @[ustack()] = count(); }' -c '../../target/release/vm-benchmark --num-accounts=10000 --num-transfer-blocks=10 --block-size=10000' -o output.txt
#
# Render info with
# $ python3.8 profile_stats.py svg | dot -Tsvg > deps.svg
# $ python3.8 profile_stats.py html > profile.html

from html import escape
from itertools import zip_longest
import re
import math
profile_raw_data = open('output.txt', encoding='latin_1')
FINAL = ("","-| end")
TOTAL = "___TOTAL"

def make_profile(profile_raw_data):
    profile = {}
    profile[FINAL] = (0, {}, {}, 999)

    IDGEN = 1000

    total = 0
    buffer = []
    recursion = set()
    for line in profile_raw_data:
        if line == '\n':
            continue
        try:
            num = int(line)
            old_b = FINAL
            (cnt, final_from, _passon, idg) = profile[FINAL]
            profile[FINAL] = (cnt+1, final_from, _passon, idg)

            old_called_from = final_from
            for b in buffer:
                if b not in profile:
                    profile[b] = (0, {}, {}, IDGEN)
                    IDGEN += 1

                (old_num, called_from, called_to, idg) = profile[b]

                if b not in old_called_from:
                    old_called_from[b] = 0
                old_called_from[b] += 1

                if old_b not in called_to:
                    called_to[old_b] = 0
                called_to[old_b] += 1

                profile[b] = (old_num + num, called_from, called_to, idg)
                old_called_from = called_from
                old_b = b
            buffer = []
            recursion = set()
            total += num
        except:
            func = line.split('+')[0].strip()
            if func[-19:-17] == "::":
                func = func[:-19]

            parts = re.split('::', func)
            func = (escape('::'.join(parts[:-1])), escape(parts[-1]))
            if func not in recursion:
                recursion.add(func)
                buffer += [ func ]
    return (total, profile)

def make_html(profile):
    (total, profile) = profile
    print('<html><body><pre>')
    print(f'<style>{open("style.css").read()}</style>')
    print("Samples  | Log. Weight  | Callers    | Function Name")
    print("---------+--------------+------------+----------------------------------------------" + ('-'*100) )
    for l in sorted(profile):
        (num, called_from, called_to, idg) = profile[l]
        stars_num = min(int((math.log(num))), 12)
        if stars_num > 1:
            stars = "+" + ('-' * (stars_num-2)) + "+"
        if stars_num == 1:
            stars = '+'
        if stars_num == 0:
            stars = ''
            continue
        print(f'<a id="R{idg}"></a><input type="checkbox" style="display: none" id="X{idg}" checked><label class="highlight" for="X{idg}">{num:8} | {stars:12} | {len(called_from):3} -> {(len(called_to)-1):3} | {l[0]}::<span class="highlight" >{l[1].strip()}</span></label>')

        ordered_from = sorted(((called_from[k],k) for k in called_from), reverse=True)
        ordered_to = sorted(((called_to[k],k) for k in called_to), reverse=True)
        print("<div>", end='')
        for (num, (lname, name)) in ordered_from:
            (_,_,_,idg) = profile[(lname, name)]
            print(f'                                     |  -> {num:5}    <a href="#R{idg}">{name:40}</a> <a class="mute" href="#R{idg}">{lname}::{name.strip()}</a>')
        for (num, (lname, name)) in ordered_to:
            (_,_,_,idg) = profile[(lname, name)]
            print(f'                                     |     {num:5} -> <a href="#R{idg}">{name:40}</a> <a class="mute" href="#R{idg}">{lname}::{name.strip()}</a>')
        print("---------+--------------+------------+----------------------------------------------" + ('-'*100) )
        print("</div>", end='')
    print("</pre>");
    try:
        svg = open("deps.svg").read()
        print(svg)
    except:
        pass
    print("</body></html>")

def make_svg(profile):
    (total, profile) = profile
    print("digraph mygraph {")
    print("  node [shape=box];")

    saved = set()
    for l in sorted(profile):
        (num, called_from, called_to, idg) = profile[l]
        ordered_from = sorted(((called_from[k],k) for k in called_from), reverse=True)
        for (num_link, (lname_from, name_from)) in ordered_from:
            (num_from,_,_,idg_from) = profile[(lname_from, name_from)]
            if num_link/total > 0.001 and idg != 999:

                if num_link/total > 0.1:
                    color = 'red'
                elif num_link/total > 0.01:
                    color = 'orange'
                else:
                    color = 'grey'


                print(f'  X{idg_from} -> X{idg} [color = {color}];')
                saved.add(l)
                saved.add((lname_from, name_from))

    for l in saved:
        (num, called_from, called_to, idg) = profile[l]
        if num/total > 0.1:
            print(f'  X{idg} [label="{l[1].strip()} ({num/total:.2%})", color=red, URL="#R{idg}"];')
        elif num/total > 0.01:
            print(f'  X{idg} [label="{l[1].strip()} ({num/total:.2%})", color=orange, URL="#R{idg}"];')

        else:
            print(f'  X{idg} [label="{l[1].strip()} ({num/total:.2%})", URL="#R{idg}"];')

    print("}")

import sys
if sys.argv[1] == 'html':
    profile = make_profile(profile_raw_data)
    make_html(profile)
if sys.argv[1] == 'svg':
    profile = make_profile(profile_raw_data)
    make_svg(profile)
