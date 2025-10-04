import os
from supabase import create_client, Client
from django.conf import settings


def get_supabase() -> Client:
    """Get Supabase client instance"""
    supabase_url = settings.SUPABASE_CONFIG['url']
    supabase_key = settings.SUPABASE_CONFIG['anon_key']

    if not supabase_url or not supabase_key:
        raise ValueError("Supabase URL and Anon Key must be set in environment variables")

    return create_client(supabase_url, supabase_key)


def get_supabase_admin() -> Client:
    """Get Supabase client with service role (admin privileges)"""
    supabase_url = settings.SUPABASE_CONFIG['url']
    supabase_key = settings.SUPABASE_CONFIG['service_key']

    if not supabase_url or not supabase_key:
        raise ValueError("Supabase URL and Service Key must be set in environment variables")

    return create_client(supabase_url, supabase_key)