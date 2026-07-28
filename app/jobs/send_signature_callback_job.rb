# frozen_string_literal: true

class SendSignatureCallbackJob
  include Sidekiq::Job

  sidekiq_options queue: :webhooks

  TRACKED_FIELD_NAMES = %w[provider_signature client_caregiver_signature supervisor_signature].freeze
  CALLBACK_ENDPOINT = 'https://app.therapypms.com/api/v1/note/signed'.freeze
  DATA_URI_PREFIX = %r{\Adata:[^;]+;base64,}i

  def perform(params = {})
    submitter = Submitter.find_by(id: params['submitter_id'])

    return unless submitter&.completed_at?

    callback_url = AccountConfig.find_by(
      account_id: submitter.account_id,
      key: AccountConfig::SIGNATURE_CALLBACK_URL_KEY
    )&.value.presence || CALLBACK_ENDPOINT

    fields = submitter.submission.template_fields || submitter.submission.template&.fields

    return unless fields

    tracked_fields = fields.select do |f|
      f['submitter_uuid'] == submitter.uuid &&
        f['type'] == 'signature' &&
        TRACKED_FIELD_NAMES.include?(f['name'])
    end

    return if tracked_fields.empty?

    attachments_index = submitter.attachments.preload(:blob).index_by(&:uuid)

    signatures = tracked_fields.filter_map do |field|
      attachment_uuid = submitter.values[field['uuid']]
      next if attachment_uuid.blank?

      attachment = attachments_index[attachment_uuid]
      next unless attachment

      encoded = encode_png_base64(attachment)
      next if encoded.blank?

      {
        field_name: field['name'],
        field_uuid: field['uuid'],
        content_type: 'image/png',
        signature: encoded
      }
    end

    return if signatures.empty?

    document = encode_document_base64(submitter)

    payload = {
      admin_id: resolve_admin_id(submitter),
      template_id: submitter.submission.template_id,
      submission_id: submitter.submission_id,
      embed_src: build_embed_src(submitter),
      email: submitter.email,
      signatures: signatures
    }

    # TherapyPMS note/signed often expects the signed PDF as base64 too.
    payload[:document] = document if document.present?
    payload[:file] = document if document.present?

    response = Faraday.post(callback_url) do |req|
      req.headers['Content-Type'] = 'application/json'
      req.body = payload.to_json
      req.options.read_timeout = 30
      req.options.open_timeout = 10
    end

    unless response.success?
      Rails.logger.error(
        "SendSignatureCallbackJob failed for submitter #{submitter.id}: " \
        "status=#{response.status} body=#{response.body.to_s.truncate(1000)}"
      )
    end
  rescue Faraday::Error => e
    Rails.logger.error("SendSignatureCallbackJob error for submitter #{params['submitter_id']}: #{e.message}")
  end

  private

  def resolve_admin_id(submitter)
    submitter.account.tpms_admin_id.presence || submitter.account_id
  end

  def build_embed_src(submitter)
    opts = Docuseal.default_url_options
    port = opts[:port] ? ":#{opts[:port]}" : ''

    "#{opts[:protocol]}://#{opts[:host]}#{port}/submissions/#{submitter.submission_id}"
  end

  def encode_document_base64(submitter)
    attachment = Submitters.select_attachments_for_download(submitter).first
    return if attachment.blank?

    Base64.strict_encode64(attachment.download)
  rescue StandardError => e
    Rails.logger.error("SendSignatureCallbackJob document encode error: #{e.message}")
    nil
  end

  # Always send clean standard base64 PNG — no data-URI prefix, no newlines.
  # This avoids TherapyPMS "invalid base 64 format" when the stored file is
  # SVG/typed-text or accidentally includes a data:image/...;base64, prefix.
  def encode_png_base64(attachment)
    raw = attachment.download
    return if raw.blank?

    raw = Base64.decode64(raw.sub(DATA_URI_PREFIX, '')) if raw.lstrip.start_with?('data:')

    png_bytes =
      begin
        Vips::Image.new_from_buffer(raw, '').write_to_buffer('.png')
      rescue StandardError
        return unless png_magic?(raw)

        raw
      end

    Base64.strict_encode64(png_bytes)
  rescue StandardError => e
    Rails.logger.error("SendSignatureCallbackJob signature encode error: #{e.message}")
    nil
  end

  def png_magic?(bytes)
    bytes.to_s.b.start_with?("\x89PNG\r\n\x1a\n".b)
  end
end
