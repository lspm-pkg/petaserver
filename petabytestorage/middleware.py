from fastapi.responses import PlainTextResponse
from fastapi import Request, Response
from fastapi.routing import APIRoute
from typing import Callable
from .globals import AUTHTOKENS
from .models import User


class AuthenticatedRoute(APIRoute):
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            if not (token := request.session.get("token")):
                return PlainTextResponse("Unauthorized", 401) 
            user_id = AUTHTOKENS.get(token)
            if not user_id:
                return PlainTextResponse("Unauthorized", 401) 
            request.state.user = (await User.filter(id=user_id))[0]
            response = await original_route_handler(request)
            return response

        return custom_route_handler
