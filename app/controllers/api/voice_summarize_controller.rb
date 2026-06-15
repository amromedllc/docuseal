# frozen_string_literal: true

module Api
  class VoiceSummarizeController < ApiBaseController
    skip_before_action :authenticate_user!
    skip_authorization_check

    def create
      unless voice_feature_enabled?
        return render json: { error: 'Not authorized' }, status: :forbidden
      end

      text = params[:text].to_s.strip

      if text.blank?
        return render json: { error: I18n.t(:voice_summarize_text_required) }, status: :unprocessable_content
      end

      if text.length > 10_000
        return render json: { error: I18n.t(:voice_summarize_text_too_long) }, status: :unprocessable_content
      end

      RateLimit.call("voice-summarize-#{request.remote_ip}", limit: 20, ttl: 1.minute, enabled: true)

      summary = VoiceSummarizer.call(text)

      render json: { summary: }
    rescue VoiceSummarizer::Error => e
      render json: { error: e.message }, status: :unprocessable_content
    rescue RateLimit::LimitApproached
      render json: { error: I18n.t(:too_many_attempts) }, status: :too_many_requests
    end

    private

    def voice_feature_enabled?
      if params[:submitter_slug].present?
        submitter = Submitter.find_by(slug: params[:submitter_slug])

        return VoiceFeature.enabled_for_submitter?(submitter) if submitter
      end

      current_user.present? && VoiceFeature.enabled_for?(account: current_account, user: current_user)
    end
  end
end
