# frozen_string_literal: true

module VoiceSummarizer
  Error = Class.new(StandardError)

  module_function

  def call(text, admin_id: nil)
    url = ENV.fetch('AI_SUMMARIZER_URL', 'https://ai-summarizer.amromed.com/api/v1/summarize')

    body = { text: text, admin_id: admin_id.to_i }

    response = Faraday.post(url) do |req|
      req.headers['Content-Type'] = 'application/json'
      req.headers['x-api-key'] = ENV['CLIENT_API_KEY'] if ENV['CLIENT_API_KEY'].present?
      req.body = body.to_json
      req.options.timeout = 30
      req.options.open_timeout = 10
    end

    unless response.success?
      raise Error, I18n.t(:voice_summarize_failed)
    end

    summary = parse_summary(JSON.parse(response.body))

    raise Error, I18n.t(:voice_summarize_failed) if summary.blank?

    summary
  rescue Faraday::Error
    raise Error, I18n.t(:voice_summarize_failed)
  rescue JSON::ParserError
    raise Error, I18n.t(:voice_summarize_failed)
  end

  def quota(admin_id)
    base_url = ENV.fetch('AI_SUMMARIZER_URL', 'https://ai-summarizer.amromed.com/api/v1/summarize')
                  .sub(%r{/[^/]+$}, '')
    url = "#{base_url}/quota/#{admin_id}"

    response = Faraday.get(url) do |req|
      req.headers['Content-Type'] = 'application/json'
      req.headers['x-api-key'] = ENV['CLIENT_API_KEY'] if ENV['CLIENT_API_KEY'].present?
      req.options.timeout = 10
      req.options.open_timeout = 5
    end

    return nil unless response.success?

    JSON.parse(response.body)
  rescue Faraday::Error, JSON::ParserError
    nil
  end

  def parse_summary(body)
    return body if body.is_a?(String)

    body['summary'].presence ||
      body['text'].presence ||
      body['result'].presence ||
      body.dig('data', 'summary').presence ||
      body.dig('data', 'text').presence
  end
end
