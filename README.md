# A very simple server for querying GitHub's advisory for a malicious NPM package

example query:

```
http GET http://127.0.0.1:13400/api/vuln/jquery
```

output (as of when i'm writing this):

```json
[
  {
    "badness": 7.95,
    "range": ">= 1.7.1, <= 1.8.3"
  },
  {
    "badness": 3.1,
    "range": "< 1.9.0"
  },
  {
    "badness": 3.1,
    "range": ">= 1.2, < 3.5.0"
  },
  {
    "badness": 3.1,
    "range": ">= 1.0.3, < 3.5.0"
  },
  {
    "badness": 3.1,
    "range": "< 3.4.0"
  },
  {
    "badness": 3,
    "range": "> 2.1.0, < 3.0.0"
  },
  {
    "badness": 3,
    "range": "< 3.0.0"
  }
]
```

## GitHub PAT API Key

You will need to put your PAT key in the `.env` file. For this project, you only need the `read:packages` permissions to be turned on.
