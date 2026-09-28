"""本地启动入口：uvicorn main:app --reload"""

import uvicorn

from auth_app.api import create_app

app = create_app()


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
