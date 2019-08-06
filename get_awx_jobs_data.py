import json
import re

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import pandas


def get_auth_token(awx_username, awx_pass, verify_ssl):

    auth_url = awx_base_url + "/api/v2/authtoken/"
    token_resp = requests.post(
                                auth_url,
                                verify=verify_ssl,
                                json={'username': awx_username, 'password': awx_pass}
                                )
    auth_token = token_resp.json()['token']
    auth_header = {"Authorization": "Token {}".format(auth_token),
                   "content-type": "application/json"}

    return auth_header


def agg_jobs_data():

    auth_token = get_auth_token(awx_username=awx_user, awx_pass=awx_password, verify_ssl=verify_ssl)
    results_df = pandas.DataFrame()
    jobs_url = awx_base_url + f"/api/v2/jobs/?page={start_page}"
    page_count = int(re.compile("page=(?P<page_number>\\d+$)").search(jobs_url).group('page_number'))
    has_next_page = True

    while has_next_page is not None:
        api_call = requests.get(
            jobs_url,
            headers=auth_token,
            verify=verify_ssl,
        )

        data = json.loads(api_call.text)
        df = pandas.io.json.json_normalize(data["results"])
        df = df[["playbook", "elapsed", "status"]]
        df.set_index("playbook", inplace=True)

        df_tmp = df.groupby("playbook").sum(numeric_only=True).astype(int)#.apply(lambda x: round(x / 60, 2))
        df_tmp["playbooks_runs_count"] = df.groupby("playbook").size()
        df_tmp["successful_playbook_runs_count"] = df.groupby("playbook").apply(lambda col: (col["status"] == "successful").sum())

        results_df = pandas.concat([results_df, df_tmp])

        has_next_page = data["next"]
        page_count += 1
        jobs_url = f"{awx_base_url}/api/v2/jobs/?page={page_count}"

    results_df = results_df.groupby("playbook").sum(numeric_only=True).sort_values(by=["elapsed"], ascending=False)
    results_df["avg_playbook_run_time"] = (results_df[["elapsed"]].div(results_df["playbooks_runs_count"], axis=0)).astype(int)

    print(results_df)
    results_df.to_csv('./playbooks_data.csv', sep='\t', encoding='utf-8')
    return results_df


if __name__ == "__main__":

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    awx_base_url = input("awx_url: ")
    start_page = 1
    awx_user = input("username: ")
    awx_password = input("password: ")
    verify_ssl = False  # set for self signed ssl certs
    print("\nprocessing..")
    agg_jobs_data()
