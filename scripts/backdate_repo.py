#!/usr/bin/env python3
"""
Backdate git commits across a 7-month window (July 2019 to March 2020)
using random number generation for dates and times, with roughly even spacing
and natural variance.
"""

import datetime
import os
import random
import subprocess
import sys

def main():
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    os.chdir(repo_dir)

    # Obtain commit hashes from root to HEAD
    cmd = ["git", "rev-list", "--reverse", "HEAD"]
    commit_hashes = subprocess.check_output(cmd).decode().strip().splitlines()
    num_commits = len(commit_hashes)
    print(f"Total commits to backdate: {num_commits}")

    random.seed(495)

    start_date = datetime.datetime(2019, 7, 22, 11, 24, 18)
    end_target = datetime.datetime(2020, 2, 25, 18, 45, 0)
    total_seconds = (end_target - start_date).total_seconds()

    # Generate random deltas with natural variance
    deltas = []
    for _ in range(num_commits - 1):
        r = random.random()
        if r < 0.15:
            # Same day burst (2 to 5 hours later)
            d = random.uniform(0.08, 0.22)
        elif r < 0.55:
            # 1 to 3 days
            d = random.uniform(1.2, 2.8)
        elif r < 0.85:
            # 3 to 5 days
            d = random.uniform(2.9, 4.8)
        else:
            # 5 to 7 days
            d = random.uniform(4.9, 6.8)
        deltas.append(d)

    sum_d = sum(deltas)
    scale = (total_seconds / 86400.0) / sum_d
    scaled_deltas = [d * scale for d in deltas]

    timestamps = [start_date]
    cur = start_date
    for sd in scaled_deltas:
        cur = cur + datetime.timedelta(days=sd)
        # Jitter hour to realistic coding hours (10:00 to 22:30)
        hour = cur.hour
        if hour < 10:
            cur = cur.replace(hour=random.randint(10, 13), minute=random.randint(5, 55), second=random.randint(10, 55))
        elif hour >= 23:
            cur = cur.replace(hour=random.randint(20, 22), minute=random.randint(5, 55), second=random.randint(10, 55))
        timestamps.append(cur)

    # Enforce strictly monotonic timestamps
    for i in range(1, len(timestamps)):
        if timestamps[i] <= timestamps[i-1]:
            timestamps[i] = timestamps[i-1] + datetime.timedelta(hours=random.uniform(2.0, 5.0))

    # Helper function to determine timezone offset (-0400 during EDT, -0500 during EST)
    # EDT 2019 ended Sunday Nov 3, 2019 at 02:00
    edt_end = datetime.datetime(2019, 11, 3, 2, 0, 0)
    def format_git_date(dt):
        tz = "-0400" if dt < edt_end else "-0500"
        return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} {tz}"

    author_name = "Aneesh"
    author_email = "aneeshkrishnaparthasarathy@gmail.com"

    new_parent = None
    old_to_new = {}

    for idx, old_hash in enumerate(commit_hashes):
        # Extract tree
        tree = subprocess.check_output(["git", "rev-parse", f"{old_hash}^{{tree}}"]).decode().strip()
        # Extract raw commit message
        msg = subprocess.check_output(["git", "log", "-n", "1", "--format=%B", old_hash]).decode()

        date_str = format_git_date(timestamps[idx])

        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = author_name
        env["GIT_AUTHOR_EMAIL"] = author_email
        env["GIT_AUTHOR_DATE"] = date_str
        env["GIT_COMMITTER_NAME"] = author_name
        env["GIT_COMMITTER_EMAIL"] = author_email
        env["GIT_COMMITTER_DATE"] = date_str

        cmd_commit = ["git", "commit-tree", tree]
        if new_parent:
            cmd_commit.extend(["-p", new_parent])

        proc = subprocess.Popen(cmd_commit, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
        stdout, _ = proc.communicate(input=msg.encode("utf-8"))
        if proc.returncode != 0:
            print(f"Error creating commit for {old_hash}", file=sys.stderr)
            sys.exit(1)

        new_commit = stdout.decode().strip()
        old_to_new[old_hash] = new_commit
        new_parent = new_commit

        subject = msg.strip().splitlines()[0] if msg.strip() else ""
        print(f"[{idx+1:2d}/{num_commits}] {date_str} -> {new_commit[:8]} {subject[:60]}")

    # Update main branch to point to newest commit
    subprocess.check_call(["git", "update-ref", "refs/heads/main", new_parent])
    subprocess.check_call(["git", "reset", "--hard", "refs/heads/main"])
    print(f"\nSuccessfully backdated all {num_commits} commits. New HEAD is {new_parent}")

if __name__ == "__main__":
    main()
