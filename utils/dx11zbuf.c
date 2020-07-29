#include <stdio.h>
#include <windows.h>
#include <d3d11.h>

/*
  doxastica-compatible dx11 fun and games
*/

ID3D11DepthStencilState *m_DepthStencilState = NULL;
ID3D11Device* pDevice = NULL;

// Disabling Z-Buffering
D3D11_DEPTH_STENCIL_DESC depthStencilDesc;

extern "C" __declspec(dllexport) void __stdcall callback(ULONG_PTR addr);
extern "C" __declspec(dllexport) void zbuf_ID3D11DrawIndexed(  UINT IndexCount, UINT StartIndexLocation,INT  BaseVertexLocation);

void zbuf_D3D11CreateDepthStencilDesc()
{
	if(pDevice != NULL)
	{
		depthStencilDesc.DepthEnable = TRUE;
		depthStencilDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
		depthStencilDesc.DepthFunc = D3D11_COMPARISON_ALWAYS;
		depthStencilDesc.StencilEnable = FALSE;
		depthStencilDesc.StencilReadMask = 0xFF;
		depthStencilDesc.StencilWriteMask = 0xFF;

		// Stencil operations if pixel is front-facing
		depthStencilDesc.FrontFace.StencilFailOp = D3D11_STENCIL_OP_KEEP;
		depthStencilDesc.FrontFace.StencilDepthFailOp = D3D11_STENCIL_OP_INCR;
		depthStencilDesc.FrontFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
		depthStencilDesc.FrontFace.StencilFunc = D3D11_COMPARISON_ALWAYS;

		// Stencil operations if pixel is back-facing
		depthStencilDesc.BackFace.StencilFailOp = D3D11_STENCIL_OP_KEEP;
		depthStencilDesc.BackFace.StencilDepthFailOp = D3D11_STENCIL_OP_DECR;
		depthStencilDesc.BackFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
		depthStencilDesc.BackFace.StencilFunc = D3D11_COMPARISON_ALWAYS;
		pDevice->CreateDepthStencilState(&depthStencilDesc, &m_DepthStencilState);
	}
	return;
}

typedef void (WINAPI * _ID3D11DrawIndexed) (UINT, UINT, INT);
_ID3D11DrawIndexed orig_ID3D11DrawIndexed = NULL;

extern "C" void __stdcall callback(ULONG_PTR addr)
{
	if(orig_ID3D11DrawIndexed == NULL)
	{
		orig_ID3D11DrawIndexed = (_ID3D11DrawIndexed )addr;
	}
	return;
}

extern "C" void zbuf_ID3D11DrawIndexed(  UINT IndexCount, UINT StartIndexLocation,INT  BaseVertexLocation)
{
	ID3D11DeviceContext *deviceContext;
	__asm{
		mov deviceContext,ecx

	}
	
	if(pDevice == NULL)
	{
		deviceContext->GetDevice(&pDevice);
		zbuf_D3D11CreateDepthStencilDesc();
	}
	
	/*
	badness here.
	*/
	
	__asm{
		mov ecx,deviceContext
	}
	orig_ID3D11DrawIndexed(IndexCount, StartIndexLocation, BaseVertexLocation);
	__asm{
		int 3
	}
	return;
}