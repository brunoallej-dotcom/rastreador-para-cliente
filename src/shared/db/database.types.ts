
export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[]

export type Database = {
  
  "public": {
          Tables: {
            "audit_events": {
                  Row: {
                    "action": string,"actor_id": string | null,"actor_role": Database["public"]['Enums']["app_role"] | null,"client_id": string | null,"id": number,"metadata": NonNullable<Json>,"occurred_at": string,"process_id": string | null,"request_id": string | null,"resource_id": string,"resource_type": string
                  }
                  ComputedFields: never
                  Insert: {
                    "action": string,"actor_id"?: string | null,"actor_role"?: Database["public"]['Enums']["app_role"] | null,"client_id"?: string | null,"id"?: never,"metadata"?: NonNullable<Json>,"occurred_at"?: string,"process_id"?: string | null,"request_id"?: string | null,"resource_id": string,"resource_type": string
                  }
                  Update: {
                    "action"?: string,"actor_id"?: string | null,"actor_role"?: Database["public"]['Enums']["app_role"] | null,"client_id"?: string | null,"id"?: never,"metadata"?: NonNullable<Json>,"occurred_at"?: string,"process_id"?: string | null,"request_id"?: string | null,"resource_id"?: string,"resource_type"?: string
                  }
                  Relationships: [
                    
                  ]
                },"clients": {
                  Row: {
                    "archived_at": string | null,"created_at": string,"id": string,"name": string,"updated_at": string
                  }
                  ComputedFields: never
                  Insert: {
                    "archived_at"?: string | null,"created_at"?: string,"id"?: string,"name": string,"updated_at"?: string
                  }
                  Update: {
                    "archived_at"?: string | null,"created_at"?: string,"id"?: string,"name"?: string,"updated_at"?: string
                  }
                  Relationships: [
                    
                  ]
                },"default_stage_template": {
                  Row: {
                    "description": string | null,"name": string,"position": number
                  }
                  ComputedFields: never
                  Insert: {
                    "description"?: string | null,"name": string,"position": number
                  }
                  Update: {
                    "description"?: string | null,"name"?: string,"position"?: number
                  }
                  Relationships: [
                    
                  ]
                },"process_stages": {
                  Row: {
                    "completed_at": string | null,"description": string | null,"id": string,"name": string,"position": number,"process_id": string,"started_at": string | null,"status": Database["public"]['Enums']["stage_status"]
                  }
                  ComputedFields: never
                  Insert: {
                    "completed_at"?: string | null,"description"?: string | null,"id"?: string,"name": string,"position": number,"process_id": string,"started_at"?: string | null,"status"?: Database["public"]['Enums']["stage_status"]
                  }
                  Update: {
                    "completed_at"?: string | null,"description"?: string | null,"id"?: string,"name"?: string,"position"?: number,"process_id"?: string,"started_at"?: string | null,"status"?: Database["public"]['Enums']["stage_status"]
                  }
                  Relationships: [
                    {
      foreignKeyName: "process_stages_process_id_fkey"
      columns: ["process_id"]
isOneToOne: false
      referencedRelation: "processes"
      referencedColumns: ["id"]
    }
                  ]
                },"processes": {
                  Row: {
                    "cancelled_at": string | null,"client_id": string,"completed_at": string | null,"created_at": string,"id": string,"status": Database["public"]['Enums']["process_status"],"title": string,"updated_at": string,"version": number
                  }
                  ComputedFields: never
                  Insert: {
                    "cancelled_at"?: string | null,"client_id": string,"completed_at"?: string | null,"created_at"?: string,"id"?: string,"status"?: Database["public"]['Enums']["process_status"],"title": string,"updated_at"?: string,"version"?: number
                  }
                  Update: {
                    "cancelled_at"?: string | null,"client_id"?: string,"completed_at"?: string | null,"created_at"?: string,"id"?: string,"status"?: Database["public"]['Enums']["process_status"],"title"?: string,"updated_at"?: string,"version"?: number
                  }
                  Relationships: [
                    {
      foreignKeyName: "processes_client_id_fkey"
      columns: ["client_id"]
isOneToOne: false
      referencedRelation: "clients"
      referencedColumns: ["id"]
    }
                  ]
                },"profiles": {
                  Row: {
                    "client_id": string | null,"created_at": string,"disabled_at": string | null,"display_name": string,"id": string,"must_change_password": boolean,"role": Database["public"]['Enums']["app_role"],"updated_at": string
                  }
                  ComputedFields: never
                  Insert: {
                    "client_id"?: string | null,"created_at"?: string,"disabled_at"?: string | null,"display_name": string,"id": string,"must_change_password"?: boolean,"role": Database["public"]['Enums']["app_role"],"updated_at"?: string
                  }
                  Update: {
                    "client_id"?: string | null,"created_at"?: string,"disabled_at"?: string | null,"display_name"?: string,"id"?: string,"must_change_password"?: boolean,"role"?: Database["public"]['Enums']["app_role"],"updated_at"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "profiles_client_id_fkey"
      columns: ["client_id"]
isOneToOne: false
      referencedRelation: "clients"
      referencedColumns: ["id"]
    }
                  ]
                },"stage_approvals": {
                  Row: {
                    "approved_at": string,"approved_by": string,"id": string,"process_id": string,"process_stage_id": string
                  }
                  ComputedFields: never
                  Insert: {
                    "approved_at"?: string,"approved_by": string,"id"?: string,"process_id": string,"process_stage_id": string
                  }
                  Update: {
                    "approved_at"?: string,"approved_by"?: string,"id"?: string,"process_id"?: string,"process_stage_id"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "stage_approvals_approved_by_fkey"
      columns: ["approved_by"]
isOneToOne: false
      referencedRelation: "profiles"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "stage_approvals_process_id_fkey"
      columns: ["process_id"]
isOneToOne: false
      referencedRelation: "processes"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "stage_approvals_stage_process_fk"
      columns: ["process_stage_id","process_id"]
isOneToOne: false
      referencedRelation: "process_stages"
      referencedColumns: ["id","process_id"]
    }
                  ]
                }
          }
          Views: {
            [_ in never]: never
          }
          Functions: {
            "consume_totp_code":
{ Args: { "p_code_digest": string,"p_factor_id": string }; Returns: boolean
                           },
"create_client":
{ Args: { "p_name": string }; Returns: {
              "archived_at": string | null,
"created_at": string,
"id": string,
"name": string,
"updated_at": string
            }
                          SetofOptions: {
        from: "*"
        to: "clients"
        isOneToOne: true
        isSetofReturn: false
      } },
"current_principal":
{ Args: Record<PropertyKey, never>; Returns: {
              "aal": string,"client_id": string,"display_name": string,"has_verified_totp": boolean,"must_change_password": boolean,"role": Database["public"]['Enums']["app_role"],"user_id": string
            }[]
                           },
"list_client_users":
{ Args: { "p_client_id": string }; Returns: {
              "created_at": string,"disabled_at": string,"display_name": string,"email": string,"last_sign_in_at": string,"must_change_password": boolean,"user_id": string
            }[]
                           },
"mark_password_changed":
{ Args: Record<PropertyKey, never>; Returns: undefined
                           },
"rate_limit_hit":
{ Args: { "p_bucket": string,"p_max": number,"p_window_seconds": number }; Returns: {
              "allowed": boolean,"retry_after_seconds": number
            }[]
                           },
"record_account_provisioned":
{ Args: { "p_user_id": string }; Returns: undefined
                           },
"require_password_change":
{ Args: { "p_user_id": string }; Returns: undefined
                           },
"set_account_disabled":
{ Args: { "p_disabled": boolean,"p_user_id": string }; Returns: undefined
                           },
"set_account_display_name":
{ Args: { "p_display_name": string,"p_user_id": string }; Returns: undefined
                           },
"update_client":
{ Args: { "p_archived"?: boolean,"p_client_id": string,"p_name"?: string }; Returns: {
              "archived_at": string | null,
"created_at": string,
"id": string,
"name": string,
"updated_at": string
            }
                          SetofOptions: {
        from: "*"
        to: "clients"
        isOneToOne: true
        isSetofReturn: false
      } }
          }
          Enums: {
            "app_role": "ceo"|"client","process_status": "active"|"completed"|"cancelled","stage_status": "pending"|"in_progress"|"completed"
          }
          CompositeTypes: {
            [_ in never]: never
          }
        }
}

type DatabaseWithoutInternals = Omit<Database, '__InternalSupabase'>

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never
> = DefaultSchemaTableNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
  ? (DefaultSchema["Tables"] & DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
      Row: infer R
    }
    ? R
    : never
  : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never
> = DefaultSchemaTableNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
  ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
      Insert: infer I
    }
    ? I
    : never
  : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never
> = DefaultSchemaTableNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
  ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
      Update: infer U
    }
    ? U
    : never
  : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never
> = DefaultSchemaEnumNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
  ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
  : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never
> = PublicCompositeTypeNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
  ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
  : never

export const Constants = {
  "public": {
          Enums: {
            "app_role": ["ceo", "client"],"process_status": ["active", "completed", "cancelled"],"stage_status": ["pending", "in_progress", "completed"]
          }
        }
} as const
