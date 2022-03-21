// Copyright © 2022 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.6.1
// source: github.com/getamis/alice/crypto/cggmp/refresh/message.proto

package refresh

import (
	commitment "github.com/getamis/alice/crypto/commitment"
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	zkproof "github.com/getamis/alice/crypto/zkproof"
	paillier "github.com/getamis/alice/crypto/zkproof/paillier"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Type int32

const (
	Type_Round1 Type = 0
	Type_Round2 Type = 1
	Type_Round3 Type = 2
)

// Enum value maps for Type.
var (
	Type_name = map[int32]string{
		0: "Round1",
		1: "Round2",
		2: "Round3",
	}
	Type_value = map[string]int32{
		"Round1": 0,
		"Round2": 1,
		"Round3": 2,
	}
)

func (x Type) Enum() *Type {
	p := new(Type)
	*p = x
	return p
}

func (x Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Type) Descriptor() protoreflect.EnumDescriptor {
	return file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_enumTypes[0].Descriptor()
}

func (Type) Type() protoreflect.EnumType {
	return &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_enumTypes[0]
}

func (x Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Type.Descriptor instead.
func (Type) EnumDescriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescGZIP(), []int{0}
}

type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type Type   `protobuf:"varint,1,opt,name=type,proto3,enum=refresh.Type" json:"type,omitempty"`
	Id   string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	// Types that are assignable to Body:
	//	*Message_Round1
	//	*Message_Round2
	//	*Message_Round3
	Body isMessage_Body `protobuf_oneof:"body"`
}

func (x *Message) Reset() {
	*x = Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescGZIP(), []int{0}
}

func (x *Message) GetType() Type {
	if x != nil {
		return x.Type
	}
	return Type_Round1
}

func (x *Message) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (m *Message) GetBody() isMessage_Body {
	if m != nil {
		return m.Body
	}
	return nil
}

func (x *Message) GetRound1() *Round1Msg {
	if x, ok := x.GetBody().(*Message_Round1); ok {
		return x.Round1
	}
	return nil
}

func (x *Message) GetRound2() *Round2Msg {
	if x, ok := x.GetBody().(*Message_Round2); ok {
		return x.Round2
	}
	return nil
}

func (x *Message) GetRound3() *Round3Msg {
	if x, ok := x.GetBody().(*Message_Round3); ok {
		return x.Round3
	}
	return nil
}

type isMessage_Body interface {
	isMessage_Body()
}

type Message_Round1 struct {
	Round1 *Round1Msg `protobuf:"bytes,4,opt,name=round1,proto3,oneof"`
}

type Message_Round2 struct {
	Round2 *Round2Msg `protobuf:"bytes,5,opt,name=round2,proto3,oneof"`
}

type Message_Round3 struct {
	Round3 *Round3Msg `protobuf:"bytes,6,opt,name=round3,proto3,oneof"`
}

func (*Message_Round1) isMessage_Body() {}

func (*Message_Round2) isMessage_Body() {}

func (*Message_Round3) isMessage_Body() {}

type HashMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PointCommitment *commitment.PointCommitmentMessage      `protobuf:"bytes,1,opt,name=pointCommitment,proto3" json:"pointCommitment,omitempty"`
	Y               *ecpointgrouplaw.EcPointMessage         `protobuf:"bytes,2,opt,name=Y,proto3" json:"Y,omitempty"`
	PedPar          *paillier.RingPederssenParameterMessage `protobuf:"bytes,3,opt,name=pedPar,proto3" json:"pedPar,omitempty"`
	Rho             []byte                                  `protobuf:"bytes,4,opt,name=rho,proto3" json:"rho,omitempty"`
	U               []byte                                  `protobuf:"bytes,5,opt,name=u,proto3" json:"u,omitempty"`
}

func (x *HashMsg) Reset() {
	*x = HashMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HashMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HashMsg) ProtoMessage() {}

func (x *HashMsg) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HashMsg.ProtoReflect.Descriptor instead.
func (*HashMsg) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescGZIP(), []int{1}
}

func (x *HashMsg) GetPointCommitment() *commitment.PointCommitmentMessage {
	if x != nil {
		return x.PointCommitment
	}
	return nil
}

func (x *HashMsg) GetY() *ecpointgrouplaw.EcPointMessage {
	if x != nil {
		return x.Y
	}
	return nil
}

func (x *HashMsg) GetPedPar() *paillier.RingPederssenParameterMessage {
	if x != nil {
		return x.PedPar
	}
	return nil
}

func (x *HashMsg) GetRho() []byte {
	if x != nil {
		return x.Rho
	}
	return nil
}

func (x *HashMsg) GetU() []byte {
	if x != nil {
		return x.U
	}
	return nil
}

type Round1Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Commitment *commitment.HashCommitmentMessage `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
}

func (x *Round1Msg) Reset() {
	*x = Round1Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Round1Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Round1Msg) ProtoMessage() {}

func (x *Round1Msg) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Round1Msg.ProtoReflect.Descriptor instead.
func (*Round1Msg) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescGZIP(), []int{2}
}

func (x *Round1Msg) GetCommitment() *commitment.HashCommitmentMessage {
	if x != nil {
		return x.Commitment
	}
	return nil
}

type Round2Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Decommitment *commitment.HashDecommitmentMessage `protobuf:"bytes,1,opt,name=decommitment,proto3" json:"decommitment,omitempty"`
}

func (x *Round2Msg) Reset() {
	*x = Round2Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Round2Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Round2Msg) ProtoMessage() {}

func (x *Round2Msg) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Round2Msg.ProtoReflect.Descriptor instead.
func (*Round2Msg) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescGZIP(), []int{3}
}

func (x *Round2Msg) GetDecommitment() *commitment.HashDecommitmentMessage {
	if x != nil {
		return x.Decommitment
	}
	return nil
}

type Round3Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ModProof     *paillier.PaillierBlumMessage  `protobuf:"bytes,1,opt,name=modProof,proto3" json:"modProof,omitempty"`
	FacProof     *paillier.NoSmallFactorMessage `protobuf:"bytes,2,opt,name=facProof,proto3" json:"facProof,omitempty"`
	SchnorrProof *zkproof.SchnorrProofMessage   `protobuf:"bytes,3,opt,name=schnorrProof,proto3" json:"schnorrProof,omitempty"`
	Encshare     []byte                         `protobuf:"bytes,4,opt,name=encshare,proto3" json:"encshare,omitempty"`
}

func (x *Round3Msg) Reset() {
	*x = Round3Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Round3Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Round3Msg) ProtoMessage() {}

func (x *Round3Msg) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Round3Msg.ProtoReflect.Descriptor instead.
func (*Round3Msg) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescGZIP(), []int{4}
}

func (x *Round3Msg) GetModProof() *paillier.PaillierBlumMessage {
	if x != nil {
		return x.ModProof
	}
	return nil
}

func (x *Round3Msg) GetFacProof() *paillier.NoSmallFactorMessage {
	if x != nil {
		return x.FacProof
	}
	return nil
}

func (x *Round3Msg) GetSchnorrProof() *zkproof.SchnorrProofMessage {
	if x != nil {
		return x.SchnorrProof
	}
	return nil
}

func (x *Round3Msg) GetEncshare() []byte {
	if x != nil {
		return x.Encshare
	}
	return nil
}

type AuxiliaryInfoKeyRefeshErrorMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ciphertext []byte `protobuf:"bytes,1,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	Plaintext  []byte `protobuf:"bytes,2,opt,name=plaintext,proto3" json:"plaintext,omitempty"`
	Mu         []byte `protobuf:"bytes,3,opt,name=mu,proto3" json:"mu,omitempty"`
}

func (x *AuxiliaryInfoKeyRefeshErrorMessage) Reset() {
	*x = AuxiliaryInfoKeyRefeshErrorMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuxiliaryInfoKeyRefeshErrorMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuxiliaryInfoKeyRefeshErrorMessage) ProtoMessage() {}

func (x *AuxiliaryInfoKeyRefeshErrorMessage) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuxiliaryInfoKeyRefeshErrorMessage.ProtoReflect.Descriptor instead.
func (*AuxiliaryInfoKeyRefeshErrorMessage) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescGZIP(), []int{5}
}

func (x *AuxiliaryInfoKeyRefeshErrorMessage) GetCiphertext() []byte {
	if x != nil {
		return x.Ciphertext
	}
	return nil
}

func (x *AuxiliaryInfoKeyRefeshErrorMessage) GetPlaintext() []byte {
	if x != nil {
		return x.Plaintext
	}
	return nil
}

func (x *AuxiliaryInfoKeyRefeshErrorMessage) GetMu() []byte {
	if x != nil {
		return x.Mu
	}
	return nil
}

var File_github_com_getamis_alice_crypto_cggmp_refresh_message_proto protoreflect.FileDescriptor

var file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDesc = []byte{
	0x0a, 0x3b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74,
	0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x2f, 0x63, 0x67, 0x67, 0x6d, 0x70, 0x2f, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x2f,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x72,
	0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x1a, 0x3b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65,
	0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x65, 0x63, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x67,
	0x72, 0x6f, 0x75, 0x70, 0x6c, 0x61, 0x77, 0x2f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x38, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x67, 0x65, 0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x2f,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x35, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74, 0x61, 0x6d, 0x69,
	0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x7a,
	0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x3e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x67, 0x65, 0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63,
	0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x2f, 0x70, 0x61,
	0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xce, 0x01, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x12, 0x21, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0d,
	0x2e, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x2e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x02, 0x69, 0x64, 0x12, 0x2c, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x2e, 0x52, 0x6f,
	0x75, 0x6e, 0x64, 0x31, 0x4d, 0x73, 0x67, 0x48, 0x00, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64,
	0x31, 0x12, 0x2c, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x12, 0x2e, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x2e, 0x52, 0x6f, 0x75, 0x6e,
	0x64, 0x32, 0x4d, 0x73, 0x67, 0x48, 0x00, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x12,
	0x2c, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x12, 0x2e, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x2e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33,
	0x4d, 0x73, 0x67, 0x48, 0x00, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x42, 0x06, 0x0a,
	0x04, 0x62, 0x6f, 0x64, 0x79, 0x22, 0xe7, 0x01, 0x0a, 0x07, 0x48, 0x61, 0x73, 0x68, 0x4d, 0x73,
	0x67, 0x12, 0x4c, 0x0a, 0x0f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x63, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x2e, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x43, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x0f,
	0x70, 0x6f, 0x69, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12,
	0x2d, 0x0a, 0x01, 0x59, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x65, 0x63, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x6c, 0x61, 0x77, 0x2e, 0x45, 0x63, 0x50,
	0x6f, 0x69, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x01, 0x59, 0x12, 0x3f,
	0x0a, 0x06, 0x70, 0x65, 0x64, 0x50, 0x61, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27,
	0x2e, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x52, 0x69, 0x6e, 0x67, 0x50, 0x65,
	0x64, 0x65, 0x72, 0x73, 0x73, 0x65, 0x6e, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x06, 0x70, 0x65, 0x64, 0x50, 0x61, 0x72, 0x12,
	0x10, 0x0a, 0x03, 0x72, 0x68, 0x6f, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x72, 0x68,
	0x6f, 0x12, 0x0c, 0x0a, 0x01, 0x75, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x75, 0x22,
	0x4e, 0x0a, 0x09, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x73, 0x67, 0x12, 0x41, 0x0a, 0x0a,
	0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x21, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x2e, 0x48, 0x61,
	0x73, 0x68, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22,
	0x54, 0x0a, 0x09, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x73, 0x67, 0x12, 0x47, 0x0a, 0x0c,
	0x64, 0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x23, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x2e,
	0x48, 0x61, 0x73, 0x68, 0x44, 0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x0c, 0x64, 0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0xe0, 0x01, 0x0a, 0x09, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33,
	0x4d, 0x73, 0x67, 0x12, 0x39, 0x0a, 0x08, 0x6d, 0x6f, 0x64, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72,
	0x2e, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x42, 0x6c, 0x75, 0x6d, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x52, 0x08, 0x6d, 0x6f, 0x64, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x3a,
	0x0a, 0x08, 0x66, 0x61, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1e, 0x2e, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x4e, 0x6f, 0x53, 0x6d,
	0x61, 0x6c, 0x6c, 0x46, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x52, 0x08, 0x66, 0x61, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x40, 0x0a, 0x0c, 0x73, 0x63,
	0x68, 0x6e, 0x6f, 0x72, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1c, 0x2e, 0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x2e, 0x53, 0x63, 0x68, 0x6e, 0x6f,
	0x72, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x0c,
	0x73, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x1a, 0x0a, 0x08,
	0x65, 0x6e, 0x63, 0x73, 0x68, 0x61, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08,
	0x65, 0x6e, 0x63, 0x73, 0x68, 0x61, 0x72, 0x65, 0x22, 0x72, 0x0a, 0x22, 0x41, 0x75, 0x78, 0x69,
	0x6c, 0x69, 0x61, 0x72, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x66, 0x65,
	0x73, 0x68, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1e,
	0x0a, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x12, 0x1c,
	0x0a, 0x09, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x12, 0x0e, 0x0a, 0x02,
	0x6d, 0x75, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x6d, 0x75, 0x2a, 0x2a, 0x0a, 0x04,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x0a, 0x0a, 0x06, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x10, 0x00,
	0x12, 0x0a, 0x0a, 0x06, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06,
	0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x10, 0x02, 0x42, 0x2f, 0x5a, 0x2d, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61,
	0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x63, 0x67, 0x67, 0x6d,
	0x70, 0x2f, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescOnce sync.Once
	file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescData = file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDesc
)

func file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescGZIP() []byte {
	file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescOnce.Do(func() {
		file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescData)
	})
	return file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDescData
}

var file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_goTypes = []interface{}{
	(Type)(0),         // 0: refresh.Type
	(*Message)(nil),   // 1: refresh.Message
	(*HashMsg)(nil),   // 2: refresh.HashMsg
	(*Round1Msg)(nil), // 3: refresh.Round1Msg
	(*Round2Msg)(nil), // 4: refresh.Round2Msg
	(*Round3Msg)(nil), // 5: refresh.Round3Msg
	(*AuxiliaryInfoKeyRefeshErrorMessage)(nil),     // 6: refresh.AuxiliaryInfoKeyRefeshErrorMessage
	(*commitment.PointCommitmentMessage)(nil),      // 7: commitment.PointCommitmentMessage
	(*ecpointgrouplaw.EcPointMessage)(nil),         // 8: ecpointgrouplaw.EcPointMessage
	(*paillier.RingPederssenParameterMessage)(nil), // 9: paillier.RingPederssenParameterMessage
	(*commitment.HashCommitmentMessage)(nil),       // 10: commitment.HashCommitmentMessage
	(*commitment.HashDecommitmentMessage)(nil),     // 11: commitment.HashDecommitmentMessage
	(*paillier.PaillierBlumMessage)(nil),           // 12: paillier.PaillierBlumMessage
	(*paillier.NoSmallFactorMessage)(nil),          // 13: paillier.NoSmallFactorMessage
	(*zkproof.SchnorrProofMessage)(nil),            // 14: zkproof.SchnorrProofMessage
}
var file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_depIdxs = []int32{
	0,  // 0: refresh.Message.type:type_name -> refresh.Type
	3,  // 1: refresh.Message.round1:type_name -> refresh.Round1Msg
	4,  // 2: refresh.Message.round2:type_name -> refresh.Round2Msg
	5,  // 3: refresh.Message.round3:type_name -> refresh.Round3Msg
	7,  // 4: refresh.HashMsg.pointCommitment:type_name -> commitment.PointCommitmentMessage
	8,  // 5: refresh.HashMsg.Y:type_name -> ecpointgrouplaw.EcPointMessage
	9,  // 6: refresh.HashMsg.pedPar:type_name -> paillier.RingPederssenParameterMessage
	10, // 7: refresh.Round1Msg.commitment:type_name -> commitment.HashCommitmentMessage
	11, // 8: refresh.Round2Msg.decommitment:type_name -> commitment.HashDecommitmentMessage
	12, // 9: refresh.Round3Msg.modProof:type_name -> paillier.PaillierBlumMessage
	13, // 10: refresh.Round3Msg.facProof:type_name -> paillier.NoSmallFactorMessage
	14, // 11: refresh.Round3Msg.schnorrProof:type_name -> zkproof.SchnorrProofMessage
	12, // [12:12] is the sub-list for method output_type
	12, // [12:12] is the sub-list for method input_type
	12, // [12:12] is the sub-list for extension type_name
	12, // [12:12] is the sub-list for extension extendee
	0,  // [0:12] is the sub-list for field type_name
}

func init() { file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_init() }
func file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_init() {
	if File_github_com_getamis_alice_crypto_cggmp_refresh_message_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HashMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Round1Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Round2Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Round3Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuxiliaryInfoKeyRefeshErrorMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Message_Round1)(nil),
		(*Message_Round2)(nil),
		(*Message_Round3)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_goTypes,
		DependencyIndexes: file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_depIdxs,
		EnumInfos:         file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_enumTypes,
		MessageInfos:      file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_msgTypes,
	}.Build()
	File_github_com_getamis_alice_crypto_cggmp_refresh_message_proto = out.File
	file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_rawDesc = nil
	file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_goTypes = nil
	file_github_com_getamis_alice_crypto_cggmp_refresh_message_proto_depIdxs = nil
}