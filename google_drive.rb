module GoogleDrive

  #TODO create object for token storing

  class Config

    # Credentials should be obtained from Google API libraries
    @params = {
      pkey: ENV['PRIVATE_KEY'],
      service_email: ENV['CLIENT_EMAIL'],
      api_host: 'https://www.googleapis.com',
      token_url: 'https://www.googleapis.com/oauth2/v4/token',
      grant: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      scope: 'https://www.googleapis.com/auth/drive'
    }

    def self.params
      @params
    end

  end


  class Request

    def self.header
      {
          alg: 'RS256',
          typ: 'JWT'
      }.to_json
    end

    def self.claimset
      {
          iss: GoogleDrive::Config.params[:service_email],
          scope: GoogleDrive::Config.params[:scope],
          aud: GoogleDrive::Config.params[:token_url],
          exp: Time.now.to_i + 60, # 1 min
          iat: Time.now.to_i
      }.to_json
    end

    def self.signature
      k = OpenSSL::PKey::RSA.new GoogleDrive::Config.params[:pkey]
      digest = OpenSSL::Digest::SHA256.new
      res = k.sign digest, "#{Base64.urlsafe_encode64 header}.#{Base64.urlsafe_encode64 claimset}"
      res
    end

    def self.get_request_params
      { 'grant_type' => GoogleDrive::Config.params[:grant],
        'assertion' => "#{Base64.urlsafe_encode64 header}.#{Base64.urlsafe_encode64 claimset}.#{Base64.urlsafe_encode64 signature}" }
    end

    def self.verify_signature(signature, token)
      k = OpenSSL::PKey::RSA.new GoogleDrive::Config.params[:pkey]
      digest = OpenSSL::Digest::SHA256.new
      k.verify(digest, Base64.urlsafe_decode64(signature), token)
    end

    def self.get_token
      uri = URI.parse GoogleDrive::Config.params[:token_url]
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Post.new(uri.request_uri)
      request.set_form_data get_request_params
      response = http.request(request)
      if response.code == '200'
        JSON(response.body)['access_token']
      else
        'none'
      end

    end

  end


  class Files

    def self.http
      uri = URI.parse GoogleDrive::Config.params[:api_host]
      http = Net::HTTP.new uri.host, uri.port
      http.use_ssl = true
      http
    end

    def self.list
      request = Net::HTTP::Get.new('/drive/v2/files')
      request.add_field 'Authorization', "Bearer #{GoogleDrive::Request.get_token}"
      response = http.request(request)
      response
    end

    def self.upload(data='', content_type = '')
      request = Net::HTTP::Post.new('/upload/drive/v2/files?uploadType=media')
      request.add_field 'Authorization', "Bearer #{GoogleDrive::Request.get_token}"
      request.add_field 'Content-Type', content_type
      request.add_field 'Content-Length', data.length
      request.body = data
      response = http.request(request)
      response
    end

    def self.update_metadata(file_id, data = '')
      request = Net::HTTP::Put.new("/drive/v2/files/#{file_id}")
      request.body = data
      request.add_field 'Content-Type', 'application/json'
      request.add_field 'Authorization', "Bearer #{GoogleDrive::Request.get_token}"
      response = http.request(request)
      response
    end

    def self.file_info(file_id)
      request = Net::HTTP::Get.new("/drive/v2/files/#{file_id}")
      request.add_field 'Authorization', "Bearer #{GoogleDrive::Request.get_token}"
      response = http.request(request)
      response
    end

    def self.permissions(file_id)
      request = Net::HTTP::Get.new("/drive/v2/files/#{file_id}/permissions")
      request.add_field 'Authorization', "Bearer #{GoogleDrive::Request.get_token}"
      response = http.request(request)
      response
    end

    def self.insert_permission(file_id, permissions = '')
      request = Net::HTTP::Post.new("/drive/v2/files/#{file_id}/permissions")
      request.body = permissions
      request.add_field 'Content-Type', 'application/json'
      request.add_field 'Authorization', "Bearer #{GoogleDrive::Request.get_token}"
      response = http.request(request)
      response
    end

    def self.insert_parent(file_id, parent_id)
      request = Net::HTTP::Post.new("/drive/v2/files/#{file_id}/parents")
      request.body = { id: parent_id }.to_json
      request.add_field 'Content-Type', 'application/json'
      request.add_field 'Authorization', "Bearer #{GoogleDrive::Request.get_token}"
      response = http.request(request)
      response
    end

    def self.delete(file_id)
      request = Net::HTTP::Delete.new("/drive/v2/files/#{file_id}")
      request.add_field 'Authorization', "Bearer #{GoogleDrive::Request.get_token}"
      response = http.request(request)
      response
    end


  end


end