# frozen_string_literal: true

module VoiceSummarizer
  Error = Class.new(StandardError)

  module_function

  def call(text)
    url = ENV.fetch('AI_SUMMARIZER_URL', 'https://ai-summarizer.amromed.com/api/v1/summarize')

    response = Faraday.post(url) do |req|
      req.headers['Content-Type'] = 'application/json'
      req.headers['x-api-key'] = ENV['CLIENT_API_KEY'] if ENV['CLIENT_API_KEY'].present?
      req.body = { text: text }.to_json
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

  def parse_summary(body)
    return body if body.is_a?(String)

    body['summary'].presence ||
      body['text'].presence ||
      body['result'].presence ||
      body.dig('data', 'summary').presence ||
      body.dig('data', 'text').presence
  end
end
