def test_search_and_sort(client, auth_header):
    # upload three small files
    names = ["bbb.txt", "aaa.txt", "ccc.txt"]
    for n in names:
        client.post("/upload",
                    files={"upload_file": (n, b"x", "text/plain")},
                    headers=auth_header)

    # search
    res = client.get("/files?search=bbb", headers=auth_header).json()
    assert len(res) == 1 and res[0]["filename"] == "bbb.txt"

    # sort by name asc
    res = client.get(
        "/files?sort_by=name&order=asc",
        headers=auth_header).json()
    assert [f["filename"] for f in res][:3] == sorted(names)

    # sort by name desc
    res = client.get(
        "/files?sort_by=name&order=desc",
        headers=auth_header).json()
    assert [f["filename"] for f in res][:3] == sorted(names, reverse=True)
