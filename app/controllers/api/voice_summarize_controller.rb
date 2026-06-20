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

      admin_id = resolve_account&.tpms_admin_id
      summary = VoiceSummarizer.call(text, admin_id: admin_id)

      quota = admin_id.present? ? VoiceSummarizer.quota(admin_id) : nil

      render json: { summary:, quota: }
    rescue VoiceSummarizer::Error => e
      render json: { error: e.message }, status: :unprocessable_content
    rescue RateLimit::LimitApproached
      render json: { error: I18n.t(:too_many_attempts) }, status: :too_many_requests
    end

    def quota
      unless voice_feature_enabled?
        return render json: { error: 'Not authorized' }, status: :forbidden
      end

      admin_id = resolve_account&.tpms_admin_id
      quota = admin_id.present? ? VoiceSummarizer.quota(admin_id) : nil

      render json: { quota: }
    end

    private

    def resolve_account
      if params[:submitter_slug].present?
        Submitter.find_by(slug: params[:submitter_slug])&.submission&.account
      else
        current_account
      end
    end

    def voice_feature_enabled?
      if params[:submitter_slug].present?
        submitter = Submitter.find_by(slug: params[:submitter_slug])

        return VoiceFeature.enabled_for_submitter?(submitter) if submitter
      end

      current_user.present? && VoiceFeature.enabled_for?(account: current_account, user: current_user)
    end
  end
end
