# frozen_string_literal: true

class SendIntakeRemoveCallbackJob
  include Sidekiq::Job

  sidekiq_options queue: :webhooks

  CALLBACK_ENDPOINT = 'https://app.therapypms.com/api/v1/intake/remove'.freeze

  def perform(params = {})
    payload = {
      admin_id: params['admin_id'],
      template_id: params['template_id'],
      submission_id: params['submission_id']
    }

    Faraday.post(CALLBACK_ENDPOINT) do |req|
      req.headers['Content-Type'] = 'application/json'
      req.body = payload.to_json
      req.options.read_timeout = 10
      req.options.open_timeout = 10
    end
  rescue Faraday::Error => e
    Rails.logger.error("SendIntakeRemoveCallbackJob error for submission #{params['submission_id']}: #{e.message}")
  end
end
