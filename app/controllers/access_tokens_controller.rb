class AccessTokensController < ApplicationController
  # Skip authentication for this method
  skip_before_action :authenticate_user!, only: [:public_by_email]

  def public_by_email
    user = User.find_by!(email: params[:email])
    access_token = user.access_token

    render json: {
      user_id: user.id,
      email: user.email,
      token: access_token.token
    }
  end
end
