class AccessTokensController < ApplicationController
  skip_before_action :authenticate_user!, only: [:public_by_email]
  skip_authorization_check only: [:public_by_email]  # <-- Add this

  def public_by_email
    user = User.find_by(email: params[:email])
    return render json: { error: "User not found" }, status: :not_found unless user

    access_token = user.access_token
    return render json: { error: "Access token not found" }, status: :not_found unless access_token

    render json: {
      user_id: user.id,
      email: user.email,
      token: access_token.token
    }
  rescue => e
    render json: { error: "Internal server error", message: e.message }, status: :internal_server_error
  end
end
