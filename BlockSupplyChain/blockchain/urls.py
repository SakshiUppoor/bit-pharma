from django.urls import path
from blockchain.utils import *
from blockchain.views import *

urlpatterns = [
    path('get_chain/', get_chain, name="get_chain"),
    path('mine_block/', mine_block, name="mine_block"),
    path('add_transaction/', add_transaction, name="add_transaction"),
    path('is_valid/', is_valid, name="is_valid"),
    path('connect_node/', connect_node, name="connect_node"),
    path('disconnect_node/', disconnect_node, name="disconnect_node"),
    path('replace_chain/', replace_chain, name="replace_chain"),
    path('get_nodes/', get_nodes, name="get_nodes"),
    path('display_chain/', display_chain, name="display_chain"),
    path('login/', user_login, name="login"),
    path('join/', register, name="register"),
    path('logout/', logout, name="logout"),
]
